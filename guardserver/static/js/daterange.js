jQuery(function(){
    var current_date = new Date((new Date()).toISOString());
    var default_from_date = new Date();
    default_from_date.setDate(default_from_date.getDate() - 7);
    $("#to-date").datepicker("setDate", current_date);
    $("#from-date").datepicker("setDate", default_from_date);

    localStorage.setItem("end_date", current_date.toISOString());
    localStorage.setItem("start_date", default_from_date.toISOString());

    $("#refresh-issues").click(function(){
        localStorage.setItem("end_date", $("#to-date").datepicker("getDate").toISOString());
        localStorage.setItem("start_date", $("#from-date").datepicker("getDate").toISOString());
        get_issues();
    })
});