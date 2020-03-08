# Ruby code for OAuth 2 in Action

Ruby + [Sinatra](http://sinatrarb.com/) solutions for exercises in [*OAuth 2 in Action*](https://www.manning.com/books/oauth-2-in-action) (ja: [『OAuth徹底入門』](https://www.shoeisha.co.jp/book/detail/9784798159294)).  

## Setup

    $ git clone https://github.com/sankichi92/oauth-in-action-ruby.git --recursive
    $ cd oauth-in-action-ruby
    $ bundle install

## Usage

The Ruby + Sinatra versions only implement mentioned in the book.  
So you must also use the original Node.js + Express versions (included as a git submodule).

For example, run ch-3-ex-1:

    $ bundle exec ruby ch-3-ex-1/client.rb
    (open a new terminal window)
    $ cd oauth-in-action/exercises/ch-3-ex-1
    $ npm install
    $ node authorizationServer.js
    (open a new terminal window)
    $ node protectedResource.js
