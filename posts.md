---
layout: page
title: Posts
tagline: Overview of recent posts
permalink: /posts.html
ref: now
order: 2
---

 <!-- skeleton-->
<h4>Post Browser</h4>
<div class="input-field">
                    <input placeholder="Search" id="searchText" type="text" required class="validate">
                    <a id="searchBtn">Search</a>
                </div>
   <div class="container">
      
<h4 style="margin-bottom: 1rem; margin-top: 1rem;">Posts</h4>
      
 <div id="posts"></div>
      <div id="navigatie" class="center">
        <p id="pageNumber"></p>
        <p>
          <input type="button" value="&lt;" id="vorige" title="Vorige" />
          <input type="button" value="&gt;" id="volgende" title="Volgende" />
        </p>
      </div>
    </div>
<script src="addedJS/index.js" type="module"></script>

 <!-- start dynamische generatie JS-->




[Go to the Home Page]({{ '/' | absolute_url }})
