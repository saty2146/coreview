$(function () {
  var dateNow = new Date();
  $('#datetimepicker1').datetimepicker({
    defaultDate:dateNow,
    format: 'DD/MM/YYYY',
  });
});
