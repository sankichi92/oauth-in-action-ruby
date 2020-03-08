# frozen_string_literal: true

require 'json'
require 'securerandom'
require 'uri'

require 'rack/auth/basic'
require 'sinatra'
require 'sinatra/json'
require 'sinatra/required_params'

Client = Struct.new(:id, :secret, :redirect_uris, :scope, keyword_init: true)

CLIENTS = [
  Client.new(
    id: 'oauth-client-1',
    secret: 'oauth-client-secret-1',
    redirect_uris: %w[http://localhost:9000/callback],
    scope: %w[foo bar],
  ),
].freeze

DATA_PATH = File.expand_path('../oauth-in-action-code/exercises/ch-5-ex-3/database.nosql', __dir__)

set :port, 9001

configure do
  File.open(DATA_PATH, 'w').close
end

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
    SecureRandom.base64
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
      redirect_uri.query = build_query(error: 'unsupported_response_type')
      redirect redirect_uri
    end

    code = SecureRandom.urlsafe_base64(6)
    $codes[code] = { request: original_params, scope: params[:scope] }

    redirect_uri.query = build_query(
      code: code,
      state: original_params[:state],
    )
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

      File.open(DATA_PATH, 'a') do |file|
        file.puts({ access_token: access_token, client_id: @client.id, scope: code[:scope] }.to_json)
        file.puts({ refresh_token: refresh_token, client_id: @client.id, scope: code[:scope] }.to_json)
      end

      json access_token: access_token, token_type: 'Bearer', refresh_token: refresh_token, scope: code[:scope].join(' ')
    else
      halt 400, json(error: 'invalid_grant')
    end
  when 'refresh_token'
    required_params :refresh_token

    token_hashes = File.readlines(DATA_PATH).map { |line| JSON.parse(line) }
    token_hashes.each_with_index do |token_hash, i|
      if params[:refresh_token] == token_hash['refresh_token']
        if @client.id == token_hash['client_id']
          access_token = generate_token
          token_hashes << { access_token: access_token, client_id: @client.id, scope: token_hash['scope'] }
          halt json(access_token: access_token, token_type: 'Bearer', refresh_token: token_hash['refresh_token'], scope: token_hash['scope'])
        else
          token_hashes.delete_at(i)
        end
      end
    ensure
      File.write(DATA_PATH, token_hashes.map(&:to_json).join("\n"))
    end

    halt 400, json(error: 'invalid_grant')
  else
    halt 400, json(error: 'unsupported_grant_type')
  end
end
