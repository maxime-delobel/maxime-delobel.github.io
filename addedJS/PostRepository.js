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
    const sortByDateDesc = (a, b) => new Date(b.Date) - new Date(a.Date);
    if(!zoekterm){
        return this.#posts.sort(sortByDateDesc).slice(0, 5);
    }
    const searchResult = this.#posts.filter(post => post.Title.toLowerCase().includes(zoekterm.toLowerCase()));
    if(searchResult.length > 5) return searchResult.slice(0,5).sort(sortByDateDesc);
    return searchResult.sort(sortByDateDesc);
  }
}
