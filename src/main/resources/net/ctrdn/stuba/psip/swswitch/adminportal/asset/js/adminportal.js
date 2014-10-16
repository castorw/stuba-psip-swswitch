$(document).ready(function() {
    $("a[data-call-api]").click(function() {
        var call_name = $(this).attr("data-call-api");
        if ($(this).attr("data-call-confirm") !== undefined) {
            var text = $(this).attr("data-call-confirm");
            if (!confirm(text)) {
                return;
            }
        }
        call_swswitch_api(call_name, null);
    });
});

function call_swswitch_api(call_name, callback) {
    $.post("/api/" + call_name, null, function(data) {
        if (data.Status !== true) {
            alert("ApiError: " + data.Error);
        } else {
            if (callback !== null) {
                callback(data);
            }
        }
    }, 'json');
}

function call_swswitch_api_params(call_name, post_data, callback) {
    $.post("/api/" + call_name, post_data, function(data) {
        if (data.Status !== true) {
            alert("ApiError: " + data.Error);
        } else {
            if (callback !== null) {
                callback(data);
            }
        }
    }, 'json');
}

function format_octet_size(bytes, precision, bps)
{
    var kilobyte = 1024;
    var megabyte = kilobyte * 1024;
    var gigabyte = megabyte * 1024;
    var terabyte = gigabyte * 1024;

    if ((bytes >= 0) && (bytes < kilobyte)) {
        return bytes + ((bps === true) ? " b/s" : " B");

    } else if ((bytes >= kilobyte) && (bytes < megabyte)) {
        return (bytes / kilobyte).toFixed(precision) + ((bps === true) ? " Kb/s" : " KB");

    } else if ((bytes >= megabyte) && (bytes < gigabyte)) {
        return (bytes / megabyte).toFixed(precision) + ((bps === true) ? " Mb/s" : " MB");

    } else if ((bytes >= gigabyte) && (bytes < terabyte)) {
        return (bytes / gigabyte).toFixed(precision) + ((bps === true) ? " Gb/s" : " GB");

    } else if (bytes >= terabyte) {
        return (bytes / terabyte).toFixed(precision) + ((bps === true) ? " Tb/s" : " TB");

    } else {
        return bytes + ' B';
    }
}

function format_date(timestamp, fmt) {
    var date = new Date(timestamp);
    function pad(value) {
        return (value.toString().length < 2) ? '0' + value : value;
    }
    return fmt.replace(/%([a-zA-Z])/g, function(_, fmtCode) {
        switch (fmtCode) {
            case 'Y':
                return date.getUTCFullYear();
            case 'M':
                return pad(date.getUTCMonth() + 1);
            case 'd':
                return pad(date.getUTCDate());
            case 'H':
                return pad(date.getUTCHours());
            case 'm':
                return pad(date.getUTCMinutes());
            case 's':
                return pad(date.getUTCSeconds());
            default:
                throw new Error('Unsupported format code: ' + fmtCode);
        }
    });
}