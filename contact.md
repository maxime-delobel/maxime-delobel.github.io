---
layout: page
title: Contact
tagline: Get in touch using the form below.
ref: Contact
order: 2
---
<script type="text/javascript"
        src="https://cdn.jsdelivr.net/npm/@emailjs/browser@4/dist/email.min.js">
</script>
<script type="text/javascript">
   (function(){
      emailjs.init({
        publicKey: "Q6l1XBXitxcfScvmb",
      });
   })();
</script>
<script src="/addedJS/mailScript.js"></script>
<div class="formDiv">
<p>Having any issues, questions or you want to connect? Feel free to leave a message using the form below!</p>
<form action="#" method="post", autocomplete="on">
    <label for="name">Name:</label>
    <input type="text" id="name" name="name" required><br>

<label for="email">Email:</label>
    <input type="email" id="email" name="_replyto" required><br>

<label for="subject">Subject:</label>
<input type="text" id="subject" name="subject" required><br>

<label for="message">Message:</label>
    <textarea id="message" name="message" rows="5" required></textarea><br>

<button type="submit" onclick="sendMail()">Send</button>
</form>
</div>

[Go to the Home Page]({{ '/' | absolute_url }})
