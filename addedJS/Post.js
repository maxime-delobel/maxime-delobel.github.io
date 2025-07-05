export default class Post{
    #Id;
    #Title;
    #Date;
    #Author;
    #ContentPreview;
    #Url;
    
    

    constructor(id, title, date, author, contentPreview, url) {
        this.#Id = id;
        this.#Title = title;
        this.#ContentPreview = contentPreview;
        this.#Author = author;
        this.#Date = date;
        this.#Url = url;
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

    get Url(){
        return this.#Url;
    }
}