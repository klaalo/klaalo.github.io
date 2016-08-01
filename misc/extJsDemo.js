$('#ctrlBox').append(new Date() + " external javascript file loaded\n");

$('#form').on('click', '#submit', function () {
    $('#ctrlBox').append(new Date() + ' user: ' + $('#username').val()
            + ' pass: ' + $('#password').val() + '\n');
});



