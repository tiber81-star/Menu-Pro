export async function onRequestGet(context) {
  return new Response('Fonction OK (GET)', { status: 200 });
}

export async function onRequestPost(context) {
  return new Response('Fonction OK (POST)', { status: 200 });
}
