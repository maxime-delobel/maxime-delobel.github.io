function sendMail(){
    let params = {
        subject: document.getElementById("subject").value,
        name: document.getElementById("name").value,
        email: document.getElementById("email").value,
        message: document.getElementById("message").value,
    }
    emailjs.send("service_07qc6uo","template_t4ugnli", params).then(alert("email has been sent!"));
}