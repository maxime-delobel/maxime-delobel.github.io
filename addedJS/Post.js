export default class Post{
    #Id;
    #Title;
    #Date;
    #Author;
    #ContentPreview;
    
    

    constructor(id, title, date, author, contentPreview) {
        this.#Id = id;
        this.#Title = title;
        this.#ContentPreview = contentPreview;
        this.#Author = author;
        this.#Date = date;
    }

    get Id() {
        return this.#Id;
    }

    get Title() {
        return this.#Title;
    }

    get ContentPreview() {
        return this.#ContentPreview;
    }

    get Author() {
        return this.#Author;
    }

    get Date() {
        return this.#Date;
    }
}