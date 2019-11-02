var util = require('util');
var mongoose = require('mongoose');
var UserModel = mongoose.model('User');
var Message = require('../proxy').Message;
var config = require('../config');
var eventproxy = require('eventproxy');
var UserProxy = require('../proxy').User;
var axios = require('axios').default;

/**
 * 需要管理员权限
 */
exports.adminRequired = function(req, res, next) {
  if (!req.session.user) {
    return res.render('notify/notify', { error: '你还没有登录。' });
  }

  if (!req.session.user.is_admin) {
    return res.render('notify/notify', { error: '需要管理员权限。' });
  }

  next();
};

/**
 * 需要登录
 */
exports.userRequired = function(req, res, next) {
  if (!req.session || !req.session.user || !req.session.user._id) {
    return res.status(403).send('forbidden!');
  }

  next();
};

exports.blockUser = function() {
  return function(req, res, next) {
    if (req.path === '/signout') {
      return next();
    }

    if (req.session.user && req.session.user.is_block && req.method !== 'GET') {
      return res.status(403).send('您已被管理员屏蔽了。有疑问请联系 @admin');
    }
    next();
  };
};

function gen_session(user, res) {
  var auth_token = user._id + '$$$$'; // 以后可能会存储更多信息，用 $$$$ 来分隔
  var opts = {
    path: '/',
    maxAge: 1000 * 60 * 60 * 24 * 30,
    signed: true,
    httpOnly: true
  };
  res.cookie(config.auth_cookie_name, auth_token, opts); //cookie 有效期30天
}

exports.gen_session = gen_session;

// 验证用户是否登录
exports.authUser = function(req, res, next) {
  var ep = new eventproxy();
  ep.fail(next);

  // Ensure current_user always has defined.
  res.locals.current_user = null;

  if (config.debug && req.cookies['mock_user']) {
    var mockUser = JSON.parse(req.cookies['mock_user']);
    req.session.user = new UserModel(mockUser);
    if (mockUser.is_admin) {
      req.session.user.is_admin = true;
    }
    return next();
  }

  ep.all('get_user', function(user) {
    if (!user) {
      return next();
    }
    user = res.locals.current_user = req.session.user = new UserModel(user);

    if (config.admins.hasOwnProperty(user.loginname)) {
      user.is_admin = true;
    }

    Message.getMessagesCount(
      user._id,
      ep.done(function(count) {
        user.messages_count = count;
        next();
      })
    );
  });

  if (req.session.user) {
    ep.emit('get_user', req.session.user);
  } else {
    // var auth_token = req.signedCookies[config.auth_cookie_name];
    // if (!auth_token) {
    //   return next();
    // }

    // var auth = auth_token.split('$$$$');
    // var user_id = auth[0];
    // console.log(req.cookies);
    // ep.done('get_user')(null, { _id: 132 });
    // UserProxy.getUserById(user_id, ep.done('get_user'));

    // 1. 解析cookie，如果有utoken，且有效，则认为是一个登录用户
    const utoken = req.cookies['utoken'];
    if (!utoken) {
      return next();
    }
    const h5dsConf = config.h5dsConf;
    const apiUrl = `${h5dsConf.apiHost}/backend/get-user`;
    axios.get(apiUrl, { headers: { 'access-token': h5dsConf.accessToken }, params: { utoken } }).then(res => {
      const h5dsUser = res.data;
      if (!h5dsUser) {
        return next();
      }
      const loginname = h5dsUser.userName;
      util
        .promisify(UserProxy.getUserByLoginName)(loginname)
        .then(bbsUser => {
          // 如果查不到，则先将 h5ds 的用户同步到论坛
          if (!bbsUser) {
            return (
              util
                .promisify(UserProxy.newAndSave)(
                  h5dsUser.nickName,
                  loginname,
                  '',
                  h5dsUser.unionId,
                  h5dsUser.avatarUrl,
                  true
                )
                // 同步完成后，再查一次
                .then(() => util.promisify(UserProxy.getUserByLoginName)(loginname))
            );
          }
          // 如果查到了，就直接返回
          return bbsUser;
        })
        .then(bbsUser => {
          // 如果用户正常，则设置登录状态
          if (bbsUser) {
            return ep.done('get_user')(null, bbsUser);
          }
          next();
        });
    });

    // User.newAndSave(loginname, loginname, passhash, email, avatarUrl, false, function(err) {
    //   if (err) {
    //     return next(err);
    //   }
    //   // 发送激活邮件
    //   mail.sendActiveMail(email, utility.md5(email + passhash + config.session_secret), loginname);
    //   res.render('sign/signup', {
    //     success: '欢迎加入 ' + config.name + '！我们已给您的注册邮箱发送了一封邮件，请点击里面的链接来激活您的帐号。'
    //   });
    // });
    // const user = {
    //   is_block: false,
    //   score: 10,
    //   topic_count: 1,
    //   reply_count: 1,
    //   follower_count: 0,
    //   following_count: 0,
    //   collect_tag_count: 0,
    //   collect_topic_count: 1,
    //   active: true,
    //   receive_reply_mail: false,
    //   receive_at_mail: false,
    //   _id: '5db55aee3eb01d40d48f0a3c',
    //   name: 'admin',
    //   loginname: '1234',
    //   avatar: 'http://www.gravatar.com/avatar/64e1b8d34f425d19e1ee2ea7236d3028?size=48',
    //   __v: 0
    // };
    // ep.done('get_user')(null, user);
  }
};
