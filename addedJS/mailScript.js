function sendMail(event) {
    event.preventDefault(); 

    let params = {
        subject: document.getElementById("subject").value,
        name: document.getElementById("name").value,
        email: document.getElementById("email").value,
        message: document.getElementById("message").value,
    };

    emailjs.send("service_07qc6uo", "template_t4ugnli", params)
        .then(function(response) {
            alert("Email has been sent!");
            console.log("SUCCESS!", response.status, response.text);
        }, function(error) {
            alert("Failed to send email: " + error.text);
            console.error("FAILED...", error);
        });
}
