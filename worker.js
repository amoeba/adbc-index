export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname === '/symbols.parquet') {
      const obj = await env.BUCKET.get('symbols.parquet');
      if (!obj) return new Response('Not found', { status: 404 });
      return new Response(obj.body, {
        headers: { 'Content-Type': 'application/octet-stream' },
      });
    }
    return env.ASSETS.fetch(request);
  },
};
