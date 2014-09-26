jQuery(function(){
        $.getJSON("/current_user", function(data){
            current_name = data.name;
            $("#current-user").append(current_name);
            localStorage.setItem("current_user", current_name);
        });
});
