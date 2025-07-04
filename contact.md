---
layout: page
title: Contact
tagline: Get in touch using the form below.
ref: Contact
order: 2
---
<div class="formDiv">
<p>Having any issues, questions or you want to connect? Feel free to leave a message using the form below!</p>
<form action="mailto:maxime.delobel@student.hogent.be" method="POST">
    <label for="name">Name:</label>
    <input type="text" id="name" name="name" required><br>

<label for="email">Email:</label>
    <input type="email" id="email" name="_replyto" required><br>

<label for="message">Message:</label>
    <textarea id="message" name="message" rows="5" required></textarea><br>

<button type="submit">Send</button>
</form>
</div>

[Go to the Home Page]({{ '/' | absolute_url }})
