---
layout: page
title: Posts
tagline: Overview of recent posts
permalink: /posts.html
ref: Posts
order: 0
description: overview of posts in this website and post browser functionality to search relevant posts
---

 <!-- skeleton-->
<h4>Post Browser</h4>
<div class="input-field">
                    <input placeholder="Search" id="searchText" type="text" required class="validate">
                    <button id="searchBtn">Search</button>
                    <button id="allPosts">All Posts</button>
                </div>
   <div class="container">
      
<h4 style="margin-bottom: 1rem; margin-top: 1rem;">Posts</h4>
      
 <div id="posts"></div>
      <div id="navigatie" class="center">
        <p id="pageNumber"></p>
        <p id="buttonContainer">
          <input type="button" value="Previous" id="vorige" title="Vorige" />
          <input type="button" value="Next" id="volgende" title="Volgende" />
        </p>
      </div>
    </div>
<script src="addedJS/index.js" type="module"></script>

 <!-- start dynamische generatie JS-->




[Go to the Home Page]({{ '/' | absolute_url }})
