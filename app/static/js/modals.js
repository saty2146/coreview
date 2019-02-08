// Open modal in AJAX callback

$('#mytable').on('click','.openPopup', function(event){
  event.preventDefault();
  jQuery.noConflict();
  var dataURL = $(this).attr('data-href');
  var iface = $(this).attr('data-iface');
  var mtittle = $(this).attr('data-mtittle');
  var html = ''
   $.ajax({
   url: dataURL,
        method: "GET",
        dataType: "json",
        async: true,
        success: function (data) {
            $.each(data, function (index, value) {
                html+="<ul><li>" + index + ": " +  value + "</li></ul>"
            });
        $(".modal-body").html(html);
        $(".modal-title").html(mtittle + ' ' + iface);
        $("#error-modal").modal('show');
        //return false;
        },
  });
});

