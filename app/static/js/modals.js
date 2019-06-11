// Open modal in AJAX callback

$('#mytable').on('click','.openPopup', function(event){
// console.log("trigger show open modal");
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
        if($.isArray(data)) {
            //  alert("a is an array!");
            $.each(data, function (i) {
//            $.each(data[i], function (index, value) {
//                html+="<ul><li>" + index + ": " +  value + "</li></ul>"
                html+="<ul><li>" + data[i]['disp_mac_addr'] + "</li></ul>"
            //});
            });
        } else{
//  alert("a is not an array!");
            $.each(data, function (index, value) {
                html+="<ul><li>" + index + ": " +  value + "</li></ul>"
            });

            }
        $(".modal-body").html(html);
        $(".modal-title").html(mtittle + ' ' + iface);
        $("#error-modal").modal('show');
        //return false;
        },
  });
  /* hidden.bs.modal event */
  $('#error-modal').on('hidden.bs.modal', function () {
// window.alert('hidden event fired!');
    $(".modal-body").html("");
    $(".modal-title").html("Loading...");
});
});
