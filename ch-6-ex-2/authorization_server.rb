# frozen_string_literal: true

require 'securerandom'
require 'uri'

require 'rack/auth/basic'
require 'sinatra'
require 'sinatra/json'
require 'sinatra/required_params'

require_relative '../lib/pseudo_database'

Client = Struct.new(:id, :secret, :redirect_uris, :scope, keyword_init: true)

CLIENTS = [
  Client.new(
    id: 'oauth-client-1',
    secret: 'oauth-client-secret-1',
    redirect_uris: %w[http://localhost:9000/callback],
    scope: %w[foo bar],
  ),
].freeze

set :port, 9001

$db = PseudoDatabase.new(File.expand_path('../oauth-in-action-code/exercises/ch-6-ex-1/database.nosql', __dir__)).tap(&:reset)

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

  def generate_token
    SecureRandom.urlsafe_base64
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

    code = SecureRandom.urlsafe_base64(6)
    $codes[code] = { request: original_params, scope: params[:scope] }

    redirect_uri.query = build_query(code: code, state: original_params[:state])
  when 'token'
    client = CLIENTS.find { |c| c.id == original_params[:client_id] }
    unless params[:scope].difference(client.scope).empty?
      redirect_uri.fragment = build_query(error: 'invalid_scope')
      redirect redirect_uri
    end

    access_token = generate_token
    $db.insert({ access_token: access_token, client_id: client.id, scope: params[:scope] })

    response_body_hash = { access_token: access_token, token_type: 'Bearer', scope: params[:scope].join(' ') }
    response_body_hash.merge!(state: original_params[:state]) if original_params[:state]

    redirect_uri.fragment = build_query(response_body_hash)
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
      access_token = generate_token
      refresh_token = generate_token

      $db.insert(
        { access_token: access_token, client_id: @client.id, scope: code[:scope] },
        { refresh_token: refresh_token, client_id: @client.id, scope: code[:scope] },
      )

      json access_token: access_token, token_type: 'Bearer', refresh_token: refresh_token, scope: code[:scope].join(' ')
    else
      halt 400, json(error: 'invalid_grant')
    end
  when 'refresh_token'
    required_params :refresh_token

    token_hashes = $db.to_a
    token_hashes.each_with_index do |token_hash, i|
      if params[:refresh_token] == token_hash[:refresh_token]
        if @client.id == token_hash[:client_id]
          access_token = generate_token
          token_hashes << { access_token: access_token, client_id: @client.id, scope: token_hash[:scope] }
          halt json(access_token: access_token, token_type: 'Bearer', refresh_token: token_hash[:refresh_token], scope: token_hash[:scope])
        else
          token_hashes.delete_at(i)
        end
      end
    ensure
      $db.replace(token_hashes)
    end

    halt 400, json(error: 'invalid_grant')
  else
    halt 400, json(error: 'unsupported_grant_type')
  end
end
