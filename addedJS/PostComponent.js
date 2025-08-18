import PostRepository from "./PostRepository.js";

export default class PostComponent {
  #postRepository;
  #numberOfPostsPerPage  = 5;
  #numberOfPostsAllPostPage = 10;
  #activePage;
  #url;
constructor() {
    this.#postRepository = new PostRepository();
    this.#url = '/jsonData/posts.json';
    
    // Restore active page from sessionStorage, default to 1
    this.#activePage = Number(sessionStorage.getItem('activePage')) || 1;

    // Restore search text from sessionStorage
    const savedSearch = sessionStorage.getItem('searchText') || '';
    if (savedSearch) {
        const searchInput = document.getElementById('searchText');
        if (searchInput) searchInput.value = savedSearch;
        this.#searchPosts(savedSearch); // load posts for saved search
    } else {
        this.#init(); // load recent posts if no search saved
    }

    // Set up click handlers
    if(document.getElementById('searchBtn')){
        document.getElementById('searchBtn').onclick = () => {
          this.#activePage = 1; 
          sessionStorage.setItem('activePage', this.#activePage);
          this.#searchPosts(document.getElementById('searchText').value);
        };
    }

    if(document.getElementById('allPosts')){
        document.getElementById('allPosts').onclick = () => {
          sessionStorage.clear();
            window.open('/allPosts.html','_blank');
        };
    }
}


  async #init(){
    await this.#loadRecentPosts();
    this.#navigatieToHtml();
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
  let posts = [];
  let allFilteredPosts = [];

  if (window.location.pathname === '/allPosts.html') {
    allFilteredPosts = this.#postRepository.posts.sort(
      (a, b) => new Date(b.Date) - new Date(a.Date)
    );
    posts = this.#postRepository.geefPostsAllpostsPage(this.#activePage, this.#numberOfPostsAllPostPage);
  } else {
    const searchValue = document.getElementById("searchText")?.value || "";
    allFilteredPosts = this.#postRepository.posts.filter(post =>
      post.Title.toLowerCase().includes(searchValue.toLowerCase())
    );
    posts = this.#postRepository.geefPosts(searchValue, this.#activePage, this.#numberOfPostsPerPage);
  }

  const postDiv = document.getElementById('posts');
  postDiv.innerHTML = '';
  const ulElement = document.createElement("ul");
  ulElement.classList.add("post-list");
  postDiv.appendChild(ulElement);

  posts.forEach(post => {
    const liElement = document.createElement("li");
    const spanElement = document.createElement("span");
    const h2Element = document.createElement("h2");
    const aElement = document.createElement("a");
    const pElement = document.createElement("p");

    spanElement.classList.add("post-meta");
    spanElement.innerText = post.Date;
    aElement.classList.add("post-link");
    aElement.setAttribute("href", post.Url);
    aElement.setAttribute("title", post.Title);
    aElement.innerText = post.Title;
    pElement.innerText = post.ContentPreview;

    aElement.addEventListener('click', () => {
    sessionStorage.setItem('searchText', document.getElementById('searchText')?.value || '');
    sessionStorage.setItem('activePage', this.#activePage);
  });

    h2Element.appendChild(aElement);
    liElement.appendChild(spanElement);
    liElement.appendChild(h2Element);
    liElement.appendChild(pElement);
    ulElement.appendChild(liElement);
  });

  // Update navigation with filtered posts
  this.#navigatieToHtml(allFilteredPosts.length);
}


#navigatieToHtml(filteredPostCount = null) {
  let aantalPaginas;
  if (window.location.pathname === '/allPosts.html') {
    aantalPaginas = Math.ceil(
      (filteredPostCount !== null ? filteredPostCount : this.#postRepository.posts.length) / this.#numberOfPostsAllPostPage
    );
  } else {
    aantalPaginas = Math.ceil(
      (filteredPostCount !== null ? filteredPostCount : this.#postRepository.posts.length) / this.#numberOfPostsPerPage
    );
  }

  const vorigeBtn = document.getElementById('vorige');
  const volgendeBtn = document.getElementById('volgende');

  const updateButtonState = () => {
    vorigeBtn.disabled = this.#activePage <= 1;
    volgendeBtn.disabled = this.#activePage >= aantalPaginas;
  };

  updateButtonState();

  vorigeBtn.onclick = () => {
    if (this.#activePage > 1) {
      this.#activePage--;
      this.#postsToHtml();
      updateButtonState();
    }
  };

  volgendeBtn.onclick = () => {
    if (this.#activePage < aantalPaginas) {
      this.#activePage++;
      this.#postsToHtml();
      updateButtonState();
    }
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
