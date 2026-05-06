// netlify/functions/token-exchange.js
// Serverless function that does the OAuth token exchange securely
// Client Secret is stored as Netlify environment variable, never exposed to browser

exports.handler = async function(event, context) {
  // Only allow POST
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  // CORS headers — allow requests from GitHub Pages and Netlify
  const headers = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Headers": "Content-Type",
    "Content-Type": "application/json",
  };

  // Handle preflight
  if (event.httpMethod === "OPTIONS") {
    return { statusCode: 200, headers, body: "" };
  }

  try {
    const body = JSON.parse(event.body || "{}");
    const { code, code_verifier, redirect_uri } = body;

    if (!code) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: "Missing code" }) };
    }

    // Client Secret from Netlify environment variable (never in code)
    const clientSecret = process.env.WEBEX_CLIENT_SECRET;
    const clientId     = process.env.WEBEX_CLIENT_ID;

    if (!clientSecret || !clientId) {
      return {
        statusCode: 500, headers,
        body: JSON.stringify({ error: "Server config missing — set WEBEX_CLIENT_ID and WEBEX_CLIENT_SECRET in Netlify env vars" })
      };
    }

    // Build token request
    const params = new URLSearchParams({
      grant_type:    "authorization_code",
      client_id:     clientId,
      client_secret: clientSecret,
      code,
      redirect_uri:  redirect_uri || "https://jguerra5.github.io/wxcc-whatsapp-adapter/callback.html",
    });

    // Add code_verifier if provided (PKCE)
    if (code_verifier) params.append("code_verifier", code_verifier);

    // Call Webex token endpoint
    const response = await fetch("https://webexapis.com/v1/access_token", {
      method:  "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body:    params.toString(),
    });

    const data = await response.json();

    if (!response.ok) {
      console.error("Webex token error:", data);
      return {
        statusCode: response.status, headers,
        body: JSON.stringify({ error: data.message || "Token exchange failed", details: data })
      };
    }

    // Return token to browser (never log it)
    return {
      statusCode: 200, headers,
      body: JSON.stringify({
        access_token:  data.access_token,
        refresh_token: data.refresh_token || "",
        expires_in:    data.expires_in || 3600,
      })
    };

  } catch(e) {
    console.error("Function error:", e);
    return {
      statusCode: 500, headers,
      body: JSON.stringify({ error: e.message })
    };
  }
};
