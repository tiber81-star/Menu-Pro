const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);
const { Resend } = require('resend');
const resend = new Resend(process.env.RESEND_API_KEY);
const crypto = require('crypto');

// ==========================================
// LOGIQUE RSA (identique à MenuPro.html)
// ==========================================
function bufferToBase64Url(buf) {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateLicenseToken(email) {
    try {
        const jwk = JSON.parse(process.env.RSA_PRIVATE_KEY);
        const keyObject = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
        
        const payload = {
            product: "MenuPro",
            version: "1.0",
            email: email,
            issuedAt: new Date().toISOString(),
            duration: "permanent"
        };
        
        const payloadBytes = Buffer.from(JSON.stringify(payload), 'utf-8');
        const encodedPayload = bufferToBase64Url(payloadBytes);
        
        const signature = crypto.sign('RSA-SHA256', payloadBytes, keyObject);
        const encodedSignature = bufferToBase64Url(signature);
        
        return `MP1.${encodedPayload}.${encodedSignature}`;
    } catch (error) {
        console.error("Erreur génération licence:", error);
        return null;
    }
}

// ==========================================
// WEBHOOK STRIPE
// ==========================================
exports.handler = async (event) => {
    const sig = event.headers['stripe-signature'];
    let stripeEvent;

    try {
        stripeEvent = stripe.webhooks.constructEvent(event.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
    } catch (err) {
        console.error("Webhook signature error:", err.message);
        return { statusCode: 400, body: `Webhook Error: ${err.message}` };
    }

    if (stripeEvent.type === 'checkout.session.completed') {
        const session = stripeEvent.data.object;
        const customerEmail = session.customer_details.email;
        
        console.log("Paiement reçu de:", customerEmail);
        
        const licenseKey = generateLicenseToken(customerEmail);
        if (!licenseKey) {
            return { statusCode: 500, body: "Erreur lors de la génération de la clé" };
        }

        try {
            await resend.emails.send({
                from: 'MenuPro <onboarding@resend.dev>',
                to: [customerEmail],
                subject: '🎉 Votre licence MenuPro est prête !',
                html: `<p>Merci pour votre achat !</p>
                       <p>Voici votre clé de licence :</p>
                       <h1 style="background:#f0f0f0;padding:10px;font-family:monospace;">${licenseKey}</h1>
                       <p>Cliquez ici pour télécharger le logiciel : <a href="https://menupro-app.netlify.app/MenuPro.html">Télécharger MenuPro</a></p>
                       <p>Ouvrez le fichier, collez la clé dans la fenêtre de licence, et profitez-en !</p>`
            });
            console.log("Email envoyé avec succès à:", customerEmail);
        } catch (emailError) {
            console.error("Erreur envoi email:", emailError);
            return { statusCode: 500, body: `Erreur email: ${emailError.message}` };
        }
    }

    return { statusCode: 200, body: 'OK' };
};
