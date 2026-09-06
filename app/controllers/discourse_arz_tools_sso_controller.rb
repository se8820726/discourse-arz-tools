# frozen_string_literal: true

class DiscourseArzToolsSsoController < ApplicationController
  layout false
  skip_before_action :verify_authenticity_token, only: %i[create_session destroy_session]

  def bridge
    render_bridge(bridge_script, "https://accounts.arzdigital.com https://arzdigital.com")
  end

  def bootstrap
    render_bridge(bootstrap_script, "https://hub.arzdigital.com", "https://accounts.arzdigital.com https://arzdigital.com")
  end

  def create_session
    token = bearer_token(request.headers["Authorization"])
    user = resolve_user(token)
    return render json: { status: "error" }, status: :unauthorized if user.nil?

    changed = current_user.nil? || current_user.id != user.id
    log_on_user(user, replay_anonymous_action: true) if changed
    response.headers["Cache-Control"] = "private, no-store"
    render json: { status: "success", changed: changed }
  end

  def destroy_session
    log_off_user if current_user.present?
    response.headers["Cache-Control"] = "private, no-store"
    render json: { status: "success" }
  end

  private

  def bearer_token(value)
    match = value.to_s.match(/\ABearer\s+(.+)\z/)
    match && match[1].strip.presence
  end

  def resolve_user(token)
    return nil if token.blank?
    identity = ::DiscourseArzTools::WebviewAuth::IdpClient.new(token).fetch_identity
    return nil if identity.nil?
    user = ::DiscourseArzTools::WebviewAuth::IdentityResolver.resolve(
      identity,
      ip: request.remote_ip,
      server_session: server_session,
    )
    user if user&.active? && !user.suspended?
  end

  def render_bridge(script, frame_ancestors, frame_sources = nil)
    nonce = SecureRandom.hex(16)
    response.headers.delete("X-Frame-Options")
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["X-Robots-Tag"] = "noindex, nofollow"
    policy = "default-src 'none'; script-src 'nonce-#{nonce}'; frame-ancestors #{frame_ancestors}"
    policy += "; frame-src #{frame_sources}; connect-src 'self'" if frame_sources
    response.headers["Content-Security-Policy"] = policy
    render html: "<!doctype html><html><head><meta charset=\"utf-8\"></head><body><script nonce=\"#{nonce}\">#{script}</script></body></html>".html_safe
  end

  def bridge_script
    <<~JS
      (()=>{'use strict';const A=new Set(['https://accounts.arzdigital.com','https://arzdigital.com']);let o=null,r=null;
      const q=(a,d)=>parent.postMessage({namespace:'arz-sso',version:1,requestId:r,action:a,data:d},o);
      addEventListener('message',async e=>{const m=e.data;if(e.source!==parent||!A.has(e.origin)||m?.namespace!=='arz-sso'||m?.version!==1||typeof m?.requestId!=='string')return;
      if(!o){if(m.action!=='arz-sso:init')return;o=e.origin;r=m.requestId;q('arz-sso:ready',{});return}if(e.origin!==o||m.requestId!==r)return;let ok=false;
      try{if(m.action==='arz-sso:login-access'&&typeof m.data?.access==='string'){const x=await fetch('/discourse-arz-tools/sso-session',{method:'POST',headers:{Authorization:'Bearer '+m.data.access},cache:'no-store',credentials:'same-origin'});ok=x.ok}
      else if(m.action==='arz-sso:logout'){const x=await fetch('/discourse-arz-tools/sso-logout',{method:'POST',cache:'no-store',credentials:'same-origin'});ok=x.ok}}catch(_e){}q('arz-sso:result',{success:ok})});})();
    JS
  end

  def bootstrap_script
    <<~JS
      (()=>{'use strict';const AO='https://accounts.arzdigital.com',RO='https://arzdigital.com';
      const rid=()=>crypto.randomUUID?.()||Date.now()+'-'+Math.random();
      function account(action,data){return new Promise(resolve=>{const id=rid(),f=document.createElement('iframe');f.hidden=true;f.src=AO+'/f?f='+(action==='accounts:logout'?'logout':'bridge')+'&t='+Date.now();let timer;
      const done=v=>{clearTimeout(timer);removeEventListener('message',on);f.remove();resolve(v)};const on=e=>{const m=e.data;if(e.origin!==AO||e.source!==f.contentWindow||m?.namespace!=='arz-accounts'||m?.version!==1||m?.requestId!==id)return;
      if(m.action==='accounts:ready'&&action!=='accounts:logout')f.contentWindow.postMessage({namespace:'arz-accounts',version:1,requestId:id,action,data:data||{}},AO);else if(m.action==='accounts:apply-result'||m.action==='accounts:status-result'||m.action==='accounts:logout')done(m.data)};
      addEventListener('message',on);f.onload=()=>f.contentWindow.postMessage({namespace:'arz-accounts',version:1,requestId:id,action:'accounts:init',data:{}},AO);timer=setTimeout(()=>done(null),5000);document.body.appendChild(f)})}
      function arz(action,pair){return new Promise(resolve=>{const id=rid(),f=document.createElement('iframe');f.hidden=true;f.src=RO+'/arz-sso-bridge/';let timer;
      const done=v=>{clearTimeout(timer);removeEventListener('message',on);f.remove();resolve(v)};const on=e=>{const m=e.data;if(e.origin!==RO||e.source!==f.contentWindow||m?.namespace!=='arz-sso'||m?.version!==1||m?.requestId!==id)return;
      if(m.action==='arz-sso:ready')f.contentWindow.postMessage({namespace:'arz-sso',version:1,requestId:id,action,data:pair?{access:pair.token,refresh:pair.refreshToken}:{}},RO);else if(m.action==='arz-sso:result')done(m.data?.success===true)};
      addEventListener('message',on);f.onload=()=>f.contentWindow.postMessage({namespace:'arz-sso',version:1,requestId:id,action:'arz-sso:init',data:{}},RO);timer=setTimeout(()=>done(false),5000);document.body.appendChild(f)})}
      async function run(){const logout=document.cookie.split('; ').some(v=>v==='arz_webview_logout=1');if(logout){document.cookie='arz_webview_logout=; Max-Age=0; Path=/discourse-arz-tools/sso-bootstrap; Secure; SameSite=Strict';await account('accounts:logout',{});await arz('arz-sso:logout');return}
      const name='arz_webview_sso=',part=document.cookie.split('; ').find(v=>v.startsWith(name));let pair=null,webview=false;
      if(part){webview=true;document.cookie='arz_webview_sso=; Max-Age=0; Path=/discourse-arz-tools/sso-bootstrap; Secure; SameSite=Strict';try{let raw=part.slice(name.length).replace(/-/g,'+').replace(/_/g,'/');raw+='='.repeat((4-raw.length%4)%4);const p=JSON.parse(decodeURIComponent(escape(atob(raw))));pair=await account('accounts:adopt-access',{token:p.token,signature:p.signature})}catch(_e){}}
      else pair=await account('accounts:status',{});
      if(!pair?.success&&!pair?.authenticated)return;if(pair.token&&pair.refreshToken)await arz('arz-sso:login-pair',pair);
      if(!webview&&pair.authenticated&&pair.token){try{const x=await fetch('/discourse-arz-tools/sso-session',{method:'POST',headers:{Authorization:'Bearer '+pair.token},cache:'no-store',credentials:'same-origin'});const result=await x.json();if(x.ok&&result.changed)parent.postMessage({namespace:'arz-sso',version:1,action:'arz-sso:reload'},location.origin)}catch(_e){}}}
      run();})();
    JS
  end
end
