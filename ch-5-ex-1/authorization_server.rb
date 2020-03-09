# frozen_string_literal: true

require 'securerandom'
require 'uri'

require 'rack/auth/basic'
require 'sinatra'
require 'sinatra/json'
require 'sinatra/required_params'

require_relative '../lib/pseudo_database'

Client = Struct.new(:id, :secret, :redirect_uris, keyword_init: true)

CLIENTS = [
  Client.new(
    id: 'oauth-client-1',
    secret: 'oauth-client-secret-1',
    redirect_uris: %w[http://localhost:9000/callback],
  ),
].freeze

set :port, 9001

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-5-ex-1/database.nosql', __dir__)).tap(&:reset)

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
    halt 401, { 'WWW-Authenticate' => %(Basic realm="#{settings.bind}:#{settings.port}") }, nil unless auth.provided?
    halt 400 unless auth.basic?

    username, password = auth.credentials
    @client = CLIENTS.find { |c| c.id == username }
    halt 401, { 'WWW-Authenticate' => %(Basic realm="#{settings.bind}:#{settings.port}") }, nil if @client.nil? || password != @client.secret
  end
end

$requests = {}
$codes = {}

get '/authorize' do
  required_params :client_id, :redirect_uri

  @client = CLIENTS.find { |c| c.id == params[:client_id] }
  halt 400, 'Unknown client' if @client.nil?
  halt 400, 'Invalid redirect URI' unless @client.redirect_uris.include?(params[:redirect_uri])

  @request_id = SecureRandom.uuid
  $requests[@request_id] = params

  erb :approve
end

post '/approve' do
  required_params :request_id

  original_params = $requests.delete(params[:request_id])
  halt 403, 'No matching authorization request' if original_params.nil?

  redirect_uri = URI.parse(original_params[:redirect_uri])

  if params[:approve]
    case original_params[:response_type]
    when 'code'
      code = SecureRandom.urlsafe_base64(6)
      $codes[code] = { request: original_params }

      redirect_uri.query = build_query(code: code, state: original_params[:state])
    else
      redirect_uri.query = build_query(error: 'unsupported_response_type')
    end
  else
    redirect_uri.query = build_query(error: 'access_denied')
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
      access_token = SecureRandom.base64
      $db.insert({ access_token: access_token, client_id: @client.id })
      json access_token: access_token, token_type: 'Bearer'
    else
      halt 400, json(error: 'invalid_grant')
    end
  else
    halt 400, json(error: 'unsupported_grant_type')
  end
end
