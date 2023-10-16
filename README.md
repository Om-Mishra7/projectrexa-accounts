# ProjectRexa SSO Service Documentation

[![Service Status](https://uptime.betterstack.com/status-badges/v1/monitor/vmy4.svg)](https://uptime.betterstack.com/?utm_source=status_badge)

## Table of Contents

- [Introduction](#introduction)
- [Installation](#installation)
- [Configuration](#configuration)
- [Application Structure](#application-structure)
- [Application Monitoring](#application-monitoring)
- [Rate Limiting](#rate-limiting)
- [Database Connections](#database-connections)
- [Headers](#headers)
- [Routes](#routes)
  - [favicon](#favicon)
  - [index](#index)
  - [sign_in](#sign_in)
  - [api_signin](#api_signin)
  - [signup](#signup)
  - [api_signup](#api_signup)
  - [sign_out](#sign_out)
  - [github_oauth](#github_oauth)
  - [github_callback](#github_callback)
  - [google_oauth](#google_oauth)
  - [google_callback](#google_callback)
  - [verify_email](#verify_email)
  - [resend_verification](#resend_verification)
  - [api_resend_verification](#api_resend_verification)
  - [account](#account)
  - [remove_session](#remove_session)
  - [forgot_password](#forgot_password)
  - [reset_password](#reset_password)
  - [version](#version)
- [Error Handling](#error-handling)

## Introduction

The ProjectRexa SSO (Single Sign-On) Service provides user authentication and authorization for ProjectRexa applications. This documentation outlines the main application logic and routes for the service.

## Installation

Before running the application, ensure that you have the required dependencies installed. You can install them using the following command:

```bash
pip install -r requirements.txt
```

After installing the dependencies, you can run the application using:

```bash
python app.py
```

## Configuration

The application relies on a configuration file (`config.py`) to manage settings such as database connections, API keys, and security parameters. Ensure that you have a valid configuration file before running the application.

## Application Structure

The application is structured as a Flask web application. The main components include:

- **app.py:** Contains the main application logic and routes.
- **functions.py:** Includes utility functions for working with databases, sessions, tokens, and more.
- **config.py:** Manages configuration parameters for the application.
- **templates:** Contains HTML templates for the application's web pages.
- **static:** Holds static files such as images.

## Application Monitoring

The application includes monitoring features using Sentry. However, this feature is currently commented out in the code. To enable Sentry, uncomment the relevant lines in the code and provide the appropriate DSN (Data Source Name).

## Rate Limiting

The application uses Flask Limiter for rate limiting. The default limit is set to 100 requests per minute per IP address. Rate limiting helps prevent abuse and ensures fair usage of the service.

## Database Connections

The application connects to both Redis and MongoDB databases. Redis is used for session management, while MongoDB stores user and token data.

## Headers

The application sets various HTTP headers for security purposes, including Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, X-Powered-By, and Permissions-Policy.

## Routes

### favicon

- **Description:** Returns the favicon for the application.
- **URL:** `/favicon.ico`
- **HTTP Method:** GET

### index

- **Description:** Returns the index page for the application. Redirects to the sign-in page if the user is not authenticated.
- **URL:** `/`
- **HTTP Method:** GET

### sign_in

- **Description:** Returns the sign-in page for the application.
- **URL:** `/sign-in`
- **HTTP Methods:** GET, POST

### api_signin

- **Description:** Handles the sign-in process for the application.
- **URL:** `/api/auth/sign-in`
- **HTTP Method:** POST

### signup

- **Description:** Returns the sign-up page for the application.
- **URL:** `/sign-up`
- **HTTP Methods:** GET, POST

### api_signup

- **Description:** Handles the sign-up process for the application.
- **URL:** `/api/auth/sign-up`
- **HTTP Method:** POST

### sign_out

- **Description:** Signs out the user, deleting the session.
- **URL:** `/sign-out`
- **HTTP Method:** GET

### github_oauth

- **Description:** Redirects the user to GitHub for authentication.
- **URL:** `/oauth/github`
- **HTTP Method:** GET

### github_callback

- **Description:** Handles the callback from GitHub after authentication.
- **URL:** `/callback/github`
- **HTTP Method:** GET

### google_oauth

- **Description:** Redirects the user to Google for authentication.
- **URL:** `/oauth/google`
- **HTTP Method:** GET

### google_callback

- **Description:** Handles the callback from Google after authentication.
- **URL:** `/callback/google`
- **HTTP Method:** GET

### verify_email

- **Description:** Verifies the email of the user.
- **URL:** `/verify-email`
- **HTTP Method:** GET

### resend_verification

- **Description:** Returns the page to resend the verification email.
- **URL:** `/resend-verification`
- **HTTP Methods:** GET, POST

### api_resend_verification

- **Description:** Handles the resend verification email process.
- **URL:** `/api/auth/resend-verification`
- **HTTP Method:** POST

### account

- **Description:** Returns the account page for the user.
- **URL:** `/account`
- **HTTP Method:** GET

### remove_session

- **Description:** Removes a session for the user.
- **URL:** `/api/auth/remove_session`
- **HTTP Method:** POST

### forgot_password

- **Description:** Returns the forgot password page for the user.
- **URL:** `/forgot-password`
- **HTTP Methods:** GET, POST

### reset_password

- **Description:** Returns the reset password page for the user.
- **URL:** `/reset-password`
- **HTTP Methods:** GET, POST

### version

- **Description:** Returns the version of the application.
- **URL:** `/version`
- **HTTP Method:** GET

## Error Handling

The application includes error handlers for 404 (Page Not Found) and 500 (Internal Server Error) responses. If a route is not found, a JSON response with a "Page not found" message is returned. In case of an internal server error, a JSON response with an "Internal server error" message is returned, and the user's session cookie is cleared.