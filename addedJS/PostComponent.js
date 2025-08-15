import PostRepository from "./PostRepository.js";

export default class PostComponent {
  #postRepository;
  #numberOfPostsPerPage  = 5;
  #activePage;
  #url;
  constructor() {
    this.#postRepository = new PostRepository();
    this.#url = '/jsonData/posts.json';
    document.getElementById('searchBtn').onclick = () => {
      this.#searchPosts(document.getElementById('searchText').value);
    };
    this.#navigatieToHtml();
    this.#loadRecentPosts();
    this.#activePage =1;
  }

  async #loadRecentPosts(){
    try{
        const response = await fetch(this.#url);
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
         const resultJSON = await response.json();
         if (resultJSON.Data) {
          this.#postRepository.addPosts(resultJSON.Data);
          this.#postsToHtml();
        } else{
          this.#showMessage('No posts have been published yet!');
        }
    }catch(rejectValue){
      this.#showMessage(
          `Something went wrong retrieving the post data: ${rejectValue}`
        );
    }
  }

  async #searchPosts(searchText) {
    if (searchText !== '') {
      // posts opvragen
      try {
        const response = await fetch(this.#url);
        if (!response.ok) {
          throw new Error(`HTTP error: ${response.status}`);
        }
        const resultJSON = await response.json();  
        const filteredPosts = resultJSON.Data.filter(post => post.Title.toLowerCase().includes(searchText.toLowerCase()));
        if(filteredPosts.length > 0){
          this.#postRepository.addPosts(resultJSON.Data);
          this.#postsToHtml("searchText");
        }
        else{
          this.#showMessage('No posts found for this search!');
        }
        }    
       
       catch (rejectValue) {
        this.#showMessage(
          `Something went wrong retrieving the post data: ${rejectValue}`
        );
      }
    } else {
      this.#showMessage('The search can not be empty!');
    }
  }

   #postsToHtml(searchText) {
    let posts = "";
    if(!searchText){
      posts = this.#postRepository.geefPosts();
    }else{
       posts = this.#postRepository.geefPosts(
      document.getElementById("searchText").value
    );
    }
    const postDiv = document.getElementById('posts');
    postDiv.innerHTML = '';
    const ulElement = document.createElement("ul");

    // paginanummer/aantalpagina's bijwerken
    const aantalPaginas = Math.ceil(
      this.#postRepository.posts.length / this.#numberOfPostsPerPage
    );
    document.getElementById('pageNumber').textContent = `${
      this.#activePage
    }/${aantalPaginas}`;

    // voor elk post:
    posts.forEach((post) => {
     const liElement = document.createElement("li");
     const spanElement = document.createElement("span");
     const h2Element = document.createElement("h2");
     const aElement= document.createElement("a");
     const pElement = document.createElement("p");

     spanElement.classList.add("post-meta");
     spanElement.innerText = post.Date;
     aElement.classList.add("post-link");
     aElement.setAttribute("href", `${post.Url}`);
     aElement.setAttribute("title", `${post.Title}`);
     aElement.innerText =  `${post.Title}`;
     pElement.innerText = `${post.ContentPreview}`;
     ulElement.classList.add("post-list");
     h2Element.appendChild(aElement);
     liElement.appendChild(spanElement);
     liElement.appendChild(h2Element);
     liElement.appendChild(pElement);
     ulElement.appendChild(liElement);
     postDiv.appendChild(ulElement);

    });
  
  }

   #navigatieToHtml() {
    const aantalPaginas = Math.ceil(
      this.#postRepository.posts.length / this.#numberOfPostsPerPage
    );

    document.getElementById('vorige').onclick = () => {
      this.#activePage = Math.max(1, this.#activePage - 1);
      this.#postsToHtml();
    };

    document.getElementById('volgende').onclick = () => {
      this.#activePage = Math.min(aantalPaginas, this.#activePage + 1);
      this.#postsToHtml();
    };
  }

  #showMessage(message) {
    document.getElementById('posts').innerHTML = '';
    document.getElementById('posts').insertAdjacentHTML(
      'beforeend',
      `
      <div>
        <p>${message}</p>
      </div>
      `
    );
  }
}
