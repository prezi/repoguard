jQuery(function(){

    var next_button = $("#next");
    var previous_button = $("#previous");

    previous_button.addClass("disabled");

    var page_state = JSON.parse(localStorage.getItem("issue_data"));


    if (page_state.size > localStorage.getItem("issues")) {
        next_button.addClass("disabled");
    }

    previous_button.click(function(){
        change_page(false, this, "#next");
    });

    next_button.click(function(){
        change_page(true, this, "#previous");
    });

    $("#false-positive").click(function(){
        localStorage.setItem("false_positive", "true");
        $(this).parent().parent().find('.active').removeClass('active');
        $(this).parent().addClass("active");
        get_issues();
    });

    $("#true-positive").click(function(){
        localStorage.setItem("false_positive", "false");
        $(this).parent().parent().find('.active').removeClass('active');
        $(this).parent().addClass("active");
        get_issues();
    })
});

function change_page(next_page, this_element, dom_element) {
    var page_state, issues_size;
    page_state = JSON.parse(localStorage.getItem("issue_data"));
    issues_size = localStorage.getItem("issues");
    if (next_page) {
        page_state.current_page += 1;
        if (page_state.current_page * page_state.size > issues_size) {
            $(this_element).addClass("disabled");
        }
    }
    else {
        if (page_state.current_page != 1) {
            page_state.current_page -= 1;
            if (page_state.current_page == 1) {
                $(this_element).addClass("disabled");
            }
        }
    }

    if ($(dom_element).hasClass("disabled")) {
        $(dom_element).removeClass("disabled");
    }
    localStorage.setItem("issue_data", JSON.stringify(page_state));
    get_issues();
}

function reset_pagination() {
    var page_state = JSON.parse(localStorage.getItem("issue_data"));
    page_state.current_page = 1;
    localStorage.setItem("issue_data", JSON.stringify(page_state));
}