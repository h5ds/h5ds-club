exports.index = function (req, res, next) {
  var q = req.query.q;
  q = encodeURIComponent(q);
  res.redirect('https://www.baidu.com/s?wd=' + q + '&si=www.h5ds.com');
};
