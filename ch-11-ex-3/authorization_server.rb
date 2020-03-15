# frozen_string_literal: true

require 'securerandom'
require 'uri'

require 'jwt'
require 'rack/auth/basic'
require 'sinatra'
require 'sinatra/json'
require 'sinatra/required_params'

Client = Struct.new(:id, :secret, :redirect_uris, :scope, keyword_init: true)
User = Struct.new(:sub, :username, :name, :email, :email_verified, :password, keyword_init: true)

CLIENTS = [
  Client.new(
    id: 'oauth-client-1',
    secret: 'oauth-client-secret-1',
    redirect_uris: %w[http://localhost:9000/callback],
    scope: %w[foo bar],
  ),
].freeze

USERS = [
  User.new(
    sub: '9XE3-JI34-00132A',
    username: 'alice',
    name: 'Alice',
    email: 'alice.wonderland@example.com',
    email_verified: true,
  ),
  User.new(
    sub: '1ZT5-OE63-57383B',
    username: 'bob',
    name: 'Bob',
    email: 'bob.loblob@example.net',
    email_verified: false,
  ),
  User.new(
    sub: 'F5Q1-L6LGG-959FS',
    username: 'carol',
    name: 'Carol',
    email: 'carol.lewis@example.net',
    email_verified: true,
  ),
].freeze

SHARED_TOKEN_SECRET = 'shared OAuth token secret!'

set :port, 9001

template :approve do
  <<~HTML
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Authorization Server</title>
      </head>
      <body>
        <p>Approve this client?</p>
        <ul>
          <li>ID: <%= @client.id %></li>
        </ul>
        <form action="/approve" method="POST">
          <input type="hidden" name="request_id" value="<%= @request_id %>">
          <label for="user">Select user:</label>
          <select name="user" id="user">
            <option value="alice">Alice</option>
            <option value="bob">Bob</option>
            <option value="carol">Carol</option>
          </select>
          <p>The client is requesting access to the following:</p>
          <ul>
            <% @scope.each do |scope| %>
              <li><label><input type="checkbox" name="scope[]" value="<%= scope %>" checked><%= scope %></label></li>
            <% end %>
          </ul>
          <input type="submit" name="approve" value="Approve">
          <input type="submit" name="deny" value="Deny">
        </form>
      </body>
    </html>
  HTML
end

helpers do
  def basic_auth!
    auth = Rack::Auth::Basic::Request.new(request.env)
    client_id, secret = if auth.provided? && auth.basic?
                          auth.credentials
                        else
                          required_params :client_id, :client_secret
                          [params[:client_id], params[:client_secret]]
                        end
    @client = CLIENTS.find { |c| c.id == client_id }
    halt 401 if @client.nil? || secret != @client.secret
  end

  def generate_jwt(sub:)
    now = Time.now
    payload = {
      iss: "http://#{settings.bind}:#{settings.port}/",
      sub: sub,
      aud: 'http://localhost:9002/',
      iat: now.to_i,
      exp: now.to_i + 5 * 60,
      jti: SecureRandom.alphanumeric(8),
    }

    JWT.encode(payload, SHARED_TOKEN_SECRET, 'HS256', { type: 'JWT' })
  end

  def get_user(username)
    USERS.find { |user| user.username == username }
  end
end

$requests = {}
$codes = {}

get '/authorize' do
  required_params :client_id, :redirect_uri, :scope

  @client = CLIENTS.find { |c| c.id == params[:client_id] }
  halt 400, 'Unknown client' if @client.nil?
  halt 400, 'Invalid redirect URI' unless @client.redirect_uris.include?(params[:redirect_uri])

  redirect_uri = URI.parse(params[:redirect_uri])
  @scope = params[:scope].split
  unless @scope.difference(@client.scope).empty?
    redirect_uri.query = build_query(error: 'invalid_scope')
    redirect redirect_uri
  end

  @request_id = SecureRandom.uuid
  $requests[@request_id] = params

  erb :approve
end

post '/approve' do
  required_params :request_id

  original_params = $requests.delete(params[:request_id])
  halt 403, 'No matching authorization request' if original_params.nil?

  redirect_uri = URI.parse(original_params[:redirect_uri])

  unless params[:approve]
    redirect_uri.query = build_query(error: 'access_denied')
    redirect redirect_uri
  end

  case original_params[:response_type]
  when 'code'
    client = CLIENTS.find { |c| c.id == original_params[:client_id] }
    unless params[:scope].difference(client.scope).empty?
      redirect_uri.query = build_query(error: 'invalid_scope')
      redirect redirect_uri
    end

    user = get_user(params[:user])
    code = SecureRandom.urlsafe_base64(6)
    $codes[code] = { request: original_params, scope: params[:scope], user: user }

    redirect_uri.query = build_query(code: code, state: original_params[:state])
  else
    redirect_uri.query = build_query(error: 'unsupported_response_type')
  end

  redirect redirect_uri
end

post '/token' do
  basic_auth!

  required_params :grant_type

  case params[:grant_type]
  when 'authorization_code'
    required_params :code

    code = $codes.delete(params[:code])
    if code && code[:request][:client_id] == @client.id
      access_token = generate_jwt(sub: code[:user].sub)
      json access_token: access_token, token_type: 'Bearer', scope: code[:scope].join(' ')
    else
      halt 400, json(error: 'invalid_grant')
    end
  else
    halt 400, json(error: 'unsupported_grant_type')
  end
end
