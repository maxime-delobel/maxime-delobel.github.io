import Post from "./Post.js";

export default class PostRepository {
  #posts = [];

  get posts() {
    return this.#posts;
  }

  addPosts(arrPosts) {
    this.#posts = arrPosts.map(
      (obj) => new Post(obj.Id, obj.Title, obj.Date, obj.Author, obj.ContentPreview, obj.Url)
    );
  }

  getPostById(id) {
    return this.#posts.find((post) => post.Id === id);
  }

  geefPosts(zoekterm,  page = 1, pageSize = 5){
   const sortByDateDesc = (a, b) => new Date(b.Date) - new Date(a.Date);
    let postsToUse = this.#posts;

    if (zoekterm) {
        postsToUse = postsToUse.filter(post => post.Title.toLowerCase().includes(zoekterm.toLowerCase()));
    }

    postsToUse = postsToUse.sort(sortByDateDesc);

    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    return postsToUse.slice(startIndex, endIndex);
  }

  geefPostsAllpostsPage(page = 1, pageSize = 10){
    const sortByDateDesc = (a, b) => new Date(b.Date) - new Date(a.Date);
    const sortedPosts = this.#posts.sort(sortByDateDesc);
    const startIndex = (page - 1) * pageSize;
    const endIndex = startIndex + pageSize;
    return sortedPosts.slice(startIndex, endIndex);
    
  }
}
