jQuery(function(){
    var issue_data = Object();
    issue_data.current_page = 1;
    issue_data.size = 10;
    localStorage.setItem("issue_data", JSON.stringify(issue_data));
    localStorage.setItem("false_positive", "false");
    localStorage.setItem("current_url", "/issues/");
    get_issues();

    $("#true-positive").click(function(){
        localStorage.setItem("false_positive", "false");
        reset_pagination();
    });

    $("#false-positive").click(function(){
        localStorage.setItem("false_positive", "false");
        reset_pagination();
    });
});

function get_issues() {
    url = localStorage.getItem("current_url");
    var false_positive = localStorage.getItem("false_positive") === "true";
    var page_state = JSON.parse(localStorage.getItem("issue_data"));
    var start_time = localStorage.getItem("start_date");
    var end_time = localStorage.getItem("end_date");
    var params = Object();
    params.start_time = start_time;
    params.end_time = end_time;
    params.from = (page_state.current_page - 1) * page_state.size;
    params.size = page_state.size;
    params.false_positive = false_positive;
    $.getJSON(url, params=params, function(data){
        add_issues_to_table(data.issues, "#issue-body");
        localStorage.setItem("issues", data.total);
    })
}

function add_issues_to_table(data, dom_element) {
    $(dom_element).empty();
    $.each(data, function(){
        var source = this["_source"];
        var status_change = source["false_positive"] == "true" ? ["<span class='glyphicon glyphicon-flag'></span><br>Valid", false]: ["<span class='glyphicon glyphicon-ban-circle'></span><br>False", true];
        var table_row = '<tr data-repo="' + source["repo_name"] + '">' +
            "<td>" + source["repo_name"] + "</td>" +
            "<td>" + $("<div />").text(source["matching_line"]).html() + "</td>" +
            '<td id="' + source["commit_id"] + '"><a href="javascript:void(0)" title="Click to show file">' + source["filename"] + "</a></td>" +
            "<td>" + source["commit_description"] + "</td>" +
            "<td title='" + source["description"] + "'>" + source["check_id"] + "</td>" +
            "<td class='reviewer'>" + source["last_reviewer"] +
            '<button type="button" class="btn btn-primary btn-status" id="' + this["id"] + '" data-status="' + status_change[1] + '">' +
            status_change[0] + '</button>' +
            "</tr>";
        $(dom_element).prepend(table_row);
        $("#" + source["commit_id"]).click(function(){
            var commit_id = $(this).attr('id');
            var params = Object();
            params.repo = $(this).closest('tr').attr('data-repo');
            params.file_path = $(this).text();
            $.get("/issue/get_contents/" + commit_id, params=params, function(data){
                $('#code-space').removeClass("prettyprinted");
                $("#code-space").append($("<div />").text(data).html());
                $("#code-holder").modal('show');
            });
        });
        $("#" + this["id"]).click(function(){
            var index_id = $(this).attr('id');
            var data_status = $(this).attr('data-status');
            var table_row = $(this).closest('tr');
            var params = Object();
            params.status = (data_status === "true");
            params.current_user = localStorage.getItem("current_user");

            $.ajax({
                url: "/issue/status/" + index_id,
                type: 'PUT',
                data: params,
                success: function(data) {
                    $(table_row).remove();
                }
            })
        })
    });
}
