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

  geefPosts(zoekterm){
    if(!zoekterm){
        return this.#posts.slice(0, 5);
    }
    const searchResult = this.#posts.filter(post => post.Title.toLowerCase().includes(zoekterm.toLowerCase()));
    if(searchResult.length > 5) return searchResult.slice(0,5);
    return searchResult;
  }
}
