

$(function () {
	$('div.content a:not(.lightbox)').tooltip({ 
	    track: true, 
	    delay: 0, 
	    showURL: false, 
	    showBody: " - ", 
	    fade: 250 
	});
	$('div.content a.truncated').tooltip({ 
	    track: false, 
	});	
	$('.showhide').show();
	$("#hidefromnonJS").removeClass("hiddenbydefault");
	$(".hideonload").slideUp("normal");
	$('.hideshow').hide();
	$('#toggle1,#toggle2').click(function(){
      $('.showhide').toggle();
      $('.hideshow').toggle();
    });	
	
	$('a#toggle_tooltips,span#toggle').show();
	$('a#toggle_tooltips').click(function(event){		
		event.preventDefault();
	  	$(this).attr('href', function(){  		
	  		$.ajax({
	  			url : this.href,
	  			success: function () {
	  				$('.tooltip').toggle();
	  			}
	  		});
	   	});
	});
	
	//Tooltips
	reloadTooltips();
	
	//Add tooltip to truncated definition list titles
	$('dt').each(function(){
		if( this.offsetWidth + 1 < this.scrollWidth){
			$(this).prop('title', $(this).text());
			$(this).tooltip();
			$(this).css('cursor', 'pointer');
		}
	});

});

function reloadTooltips() {
	var title = $("a[title]").not('.lightbox');
	$.each(title, function(index, value) {
		var value = $(this).attr('title');
		value = value.replace(/^([^<h3>].+?) - /,"<h3>$1</h3>");
		$(this).tooltip({content: value});
	});
}
		
function getCookie(name) {
  var dc = document.cookie;
  var prefix = name + "=";
  var begin = dc.indexOf("; " + prefix);
  if (begin == -1) {
    begin = dc.indexOf(prefix);
    if (begin != 0) return null;
  } else
    begin += 2;
  var end = document.cookie.indexOf(";", begin);
  if (end == -1)
    end = dc.length;
  return unescape(dc.substring(begin + prefix.length, end));
}