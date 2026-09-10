export async function onRequestGet(context) {
  return new Response('Webhook MenuPro actif', { status: 200 });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  
  const body = await request.text();
  const sig = request.headers.get('stripe-signature');
  
  let stripeEvent;
  try {
    stripeEvent = await verifyStripeSignature(body, sig, env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return new Response(`Webhook Error: ${err.message}`, { status: 400 });
  }

  if (stripeEvent.type === 'checkout.session.completed') {
    const session = stripeEvent.data.object;
    const customerEmail = session.customer_details.email;
    
    const licenseKey = await generateLicenseToken(customerEmail, env.RSA_PRIVATE_KEY);
    if (!licenseKey) {
      return new Response("Erreur génération clé", { status: 500 });
    }

    const emailResponse = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${env.RESEND_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        from: 'MenuPro <onboarding@resend.dev>',
        to: customerEmail,
        subject: '🎉 Votre licence MenuPro est prête !',
        html: `<p>Merci pour votre achat !</p>
               <p>Voici votre clé de licence :</p>
               <h1 style="background:#f0f0f0;padding:10px;font-family:monospace;">${licenseKey}</h1>
               <p>Cliquez ici pour télécharger le logiciel : <a href="https://menu-pro1.pages.dev/MenuPro.html">Télécharger MenuPro</a></p>
               <p>Ouvrez le fichier, collez la clé dans la fenêtre de licence, et profitez-en !</p>`
      })
    });

    if (!emailResponse.ok) {
      const error = await emailResponse.text();
      return new Response(`Erreur email: ${error}`, { status: 500 });
    }
  }

  return new Response('OK', { status: 200 });
}

async function verifyStripeSignature(payload, sig, secret) {
  const encoder = new TextEncoder();
  const parts = sig.split(',');
  const timestamp = parts.find(p => p.startsWith('t=')).split('=')[1];
  const signatures = parts.filter(p => p.startsWith('v1=')).map(p => p.split('=')[1]);
  
  const signedPayload = `${timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    'raw',
    encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['verify']
  );
  
  for (const signature of signatures) {
    const sigBytes = hexToBytes(signature);
    const valid = await crypto.subtle.verify('HMAC', key, sigBytes, encoder.encode(signedPayload));
    if (valid) {
      return JSON.parse(payload);
    }
  }
  throw new Error('Signature invalide');
}

async function generateLicenseToken(email, privateKeyJwk) {
  try {
    const jwk = JSON.parse(privateKeyJwk);
    
    const privateKey = await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['sign']
    );
    
    const payload = {
      product: "MenuPro",
      version: "1.0",
      email: email,
      issuedAt: new Date().toISOString(),
      duration: "permanent"
    };
    
    const encoder = new TextEncoder();
    const payloadBytes = encoder.encode(JSON.stringify(payload));
    
    const signature = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', privateKey, payloadBytes);
    
    const payloadBase64 = btoa(String.fromCharCode(...payloadBytes))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const signatureBase64 = btoa(String.fromCharCode(...new Uint8Array(signature)))
      .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    
    return `MP1.${payloadBase64}.${signatureBase64}`;
  } catch (error) {
    console.error("Erreur génération licence:", error);
    return null;
  }
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
