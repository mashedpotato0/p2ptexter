const { listen } = window.__TAURI__.event;
const { invoke } = window.__TAURI__.core;
const { LazyStore } = window.__TAURI__.store;

const store = new LazyStore(".settings.dat");

// ── app state ────────────────────────────────────────────────────────────────
let myPeerId = null;
let myNickname = '';
let activePeerId = null;
let peers = new Map();  // peer_id -> { name, status, avatar, lastMsg, lastTime, e2eReady }
let messages = new Map();  // peer_id -> [{ text, sent, time, nick }]
let unreadCounts = new Map();  // peer_id -> number
let searchQuery = '';

// ── dom refs ─────────────────────────────────────────────────────────────────
const myNickEl = document.getElementById('my-nickname');
const myPeerIdEl = document.getElementById('my-peer-id');
const myAvatarWrap = document.getElementById('my-avatar-wrap');
const myAvatarEl = document.getElementById('my-avatar');
const contactsListEl = document.getElementById('contacts-list');
const contactsEmpty = document.getElementById('contacts-empty');
const activeChatEl = document.getElementById('active-chat');
const noChatEl = document.getElementById('no-chat-selected');
const messageListEl = document.getElementById('message-list');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const chatNameEl = document.getElementById('chat-name');
const chatAvatarEl = document.getElementById('chat-avatar');
const chatStatusEl = document.getElementById('chat-status');
const backBtn = document.getElementById('back-btn');
const appWrapper = document.getElementById('app-wrapper');
const encIndicator = document.getElementById('enc-indicator');
const searchInput = document.getElementById('search-input');

// modals
const nicknameModal = document.getElementById('nickname-modal');
const nicknameInput = document.getElementById('nickname-input');
const confirmNick = document.getElementById('confirm-nickname');
const editNickModal = document.getElementById('edit-nick-modal');
const editNickInput = document.getElementById('edit-nick-input');
const cancelEditNick = document.getElementById('cancel-edit-nick');
const confirmEditNick = document.getElementById('confirm-edit-nick');
const editNickBtn = document.getElementById('edit-nick-btn');
const addFriendModal = document.getElementById('add-friend-modal');
const friendIdInput = document.getElementById('friend-id-input');
const confirmAddFriend = document.getElementById('confirm-add-friend');
const cancelModal = document.getElementById('cancel-modal');
const addFriendBtn = document.getElementById('add-friend-btn');
const qrModal = document.getElementById('qr-modal');
const closeQrModal = document.getElementById('close-qr-modal');
const qrPeerIdEl = document.getElementById('qr-peer-id');
let qrInstance = null;

// qr scanner
const scanQrBtn = document.getElementById('scan-qr-btn');
const qrScannerModal = document.getElementById('qr-scanner-modal');
const closeScannerModal = document.getElementById('close-scanner-modal');
let html5QrScanner = null;

// settings
const settingsBtn = document.getElementById('settings-btn');
const settingsModal = document.getElementById('settings-modal');
const closeSettingsBtn = document.getElementById('close-settings-btn');
const resetAppBtn = document.getElementById('reset-app-btn');
const bootstrapInput = document.getElementById('bootstrap-input');
const confirmBootstrap = document.getElementById('confirm-bootstrap');

// ── helpers ──────────────────────────────────────────────────────────────────
function avatarUrl(seed) {
    return `https://api.dicebear.com/7.x/bottts/svg?seed=${encodeURIComponent(seed)}`;
}

function timeStr() {
    return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

// ── initialise ───────────────────────────────────────────────────────────────
async function init() {
    console.log('init starting up');

    // listen for all p2p events from rust
    await listen('p2p-event', (event) => {
        const p = event.payload;
        console.log('p2p event', p.event_type, p);
        switch (p.event_type) {
            case 'PeerOnline': onPeerOnline(p.peer_id, p.nickname); break;
            case 'PeerOffline': onPeerOffline(p.peer_id); break;
            case 'PeerDiscovered': onPeerDiscovered(p.peer_id, p.nickname); break;
            case 'PeerExpired': onPeerExpired(p.peer_id); break;
            case 'MessageReceived': onMessageReceived(p.peer_id, p.content, p.nickname); break;
            case 'KeyExchanged': onKeyExchanged(p.peer_id, p.nickname); break;
            case 'SyncComplete': onSyncComplete(p.peer_id, p.count); break;
            default: break;
        }
    });

    // load saved data from store
    try {
        const savedNick = await store.get('nickname');
        if (savedNick) applyNickname(savedNick);

        const savedPeers = await store.get('peers');
        if (savedPeers) {
            peers = new Map(Object.entries(savedPeers));
            // marking all as offline initially until discovered or dialed
            peers.forEach(p => {
                p.status = 'offline';
                p.e2eReady = false;
            });
            renderContactsList();
        }

        const savedMessages = await store.get('messages');
        if (savedMessages) messages = new Map(Object.entries(savedMessages));

        console.log('store loaded');
    } catch (e) {
        console.error('failed to load store', e);
    }

    // grab our peer id
    try {
        myPeerId = await invoke('get_my_peer_id');
        myPeerIdEl.textContent = myPeerId;
        myAvatarEl.src = avatarUrl(myPeerId);
        console.log('my peer id', myPeerId);
    } catch (e) {
        myPeerIdEl.textContent = 'error: ' + e;
        console.error('failed to get peer id', e);
    }

    // prompt for nickname if not set
    if (!myNickname) {
        nicknameModal.classList.remove('hidden');
    }
}

async function saveState() {
    try {
        await store.set('nickname', myNickname);
        await store.set('peers', Object.fromEntries(peers));
        await store.set('messages', Object.fromEntries(messages));
        await store.save();
    } catch (e) {
        console.error('failed to save state', e);
    }
}

function applyNickname(name) {
    myNickname = name;
    myNickEl.textContent = name;
}

// ── peer events ───────────────────────────────────────────────────────────────
function onPeerDiscovered(peerId, nickname) {
    if (peerId === myPeerId) return;
    if (!peers.has(peerId)) {
        peers.set(peerId, {
            name: nickname || `Peer·${peerId.substring(0, 6)}`,
            status: 'online',
            lastMsg: 'Joined the network',
            lastTime: timeStr(),
            avatar: avatarUrl(peerId),
            e2eReady: false,
        });
        unreadCounts.set(peerId, 0);
    } else {
        const p = peers.get(peerId);
        p.status = 'online';
        if (nickname && nickname.trim()) p.name = nickname;
        peers.set(peerId, p);

        // if this is the active chat, update the header name immediately
        if (activePeerId === peerId) {
            chatNameEl.textContent = p.name;
        }
    }
    renderContactsList();
    saveState();
}

function onPeerOnline(peerId, nickname) {
    if (peerId === myPeerId) return;
    if (!peers.has(peerId)) {
        // if we didn't have them and we get a signal, they are added manually or by hello
        onPeerDiscovered(peerId, nickname);
    }
    const p = peers.get(peerId);
    p.status = 'online';
    if (p.connTimeout) {
        clearTimeout(p.connTimeout);
        p.connTimeout = null;
    }
    if (nickname && nickname.trim()) p.name = nickname;
    renderContactsList();
    if (activePeerId === peerId) {
        chatStatusEl.textContent = 'online';
        updateEncIndicator(p.e2eReady, peerId);
    }
    saveState();
}

function onPeerOffline(peerId) {
    const p = peers.get(peerId);
    if (p) {
        p.status = 'offline';
        if (p.connTimeout) {
            clearTimeout(p.connTimeout);
            p.connTimeout = null;
        }
        p.e2eReady = false;
        renderContactsList();
        if (activePeerId === peerId) {
            chatStatusEl.textContent = 'offline';
            updateEncIndicator(false, peerId);
        }
    }
}

function onPeerExpired(peerId) {
    onPeerOffline(peerId);
}

function onKeyExchanged(peerId, nickname) {
    const p = peers.get(peerId);
    if (p) {
        p.e2eReady = true;
        p.status = 'online';
        if (nickname && nickname.trim()) p.name = nickname;
        peers.set(peerId, p);
    }
    if (activePeerId === peerId) {
        updateEncIndicator(true, peerId);
        if (p) {
            chatNameEl.textContent = p.name;
            chatStatusEl.textContent = 'online';
        }
    }
    renderContactsList();
    saveState();
}

function onSyncComplete(peerId, count) {
    console.log(`sync complete for ${peerId} — ${count} messages flushed`);
    const p = peers.get(peerId);
    if (p) {
        p.lastMsg = `↺ ${count} queued message${count !== 1 ? 's' : ''} delivered`;
        p.lastTime = timeStr();
        peers.set(peerId, p);
        renderContactsList();
    }
}

function onMessageReceived(peerId, content, nickname) {
    if (!peers.has(peerId)) {
        onPeerDiscovered(peerId, nickname);
    }

    const t = timeStr();
    const p = peers.get(peerId);
    if (!messages.has(peerId)) messages.set(peerId, []);
    messages.get(peerId).push({ 
        text: content, 
        sent: false, 
        time: t, 
        nick: nickname || '', 
        ts: Date.now() // using current time for display order if not provided
    });

    p.lastMsg = content;
    p.lastTime = t;
    peers.set(peerId, p);

    if (activePeerId === peerId) {
        renderMessages();
    } else {
        // increment unread badge
        unreadCounts.set(peerId, (unreadCounts.get(peerId) || 0) + 1);
    }
    renderContactsList();
    saveState();
}

// ── render helpers ────────────────────────────────────────────────────────────
function renderContactsList() {
    contactsListEl.innerHTML = '';
    const query = searchQuery.toLowerCase();
    let count = 0;

    peers.forEach((peer, id) => {
        if (query && !peer.name.toLowerCase().includes(query) && !id.toLowerCase().includes(query)) return;
        count++;

        const unread = unreadCounts.get(id) || 0;
        const item = document.createElement('div');
        item.className = `contact-item ${activePeerId === id ? 'active' : ''}`;
        item.dataset.peerId = id;

        item.innerHTML = `
            <div class="contact-avatar-wrap">
                <img src="${peer.avatar}" class="avatar" alt="${peer.name}">
                <div class="status-dot ${peer.status}"></div>
            </div>
            <div class="contact-info-text">
                <div class="contact-name-row">
                    <span class="contact-name">${escHtml(peer.name)}</span>
                    <span class="last-time">${peer.lastTime || ''}</span>
                </div>
                <span class="last-msg">${escHtml(peer.lastMsg || '')}</span>
            </div>
            ${unread > 0 ? `<div class="unread-badge">${unread}</div>` : ''}
        `;

        item.addEventListener('click', () => selectChat(id));
        contactsListEl.appendChild(item);
    });

    contactsEmpty.style.display = count === 0 ? '' : 'none';
}

function renderMessages() {
    messageListEl.innerHTML = '';
    const msgs = messages.get(activePeerId) || [];

    msgs.forEach(msg => {
        const el = document.createElement('div');
        el.className = `message ${msg.sent ? 'sent' : 'received'}`;
        el.innerHTML = `${escHtml(msg.text)}<span class="message-time">${msg.time}</span>`;
        messageListEl.appendChild(el);
    });

    messageListEl.scrollTop = messageListEl.scrollHeight;
}

function updateEncIndicator(ready, peerId) {
    if (ready) {
        encIndicator.classList.remove('pending');
        encIndicator.querySelector('span').textContent = 'E2E Encrypted';
    } else {
        const p = peers.get(peerId);
        const label = p?.status === 'offline' ? 'Peer offline' : 'Exchanging keys…';
        encIndicator.classList.add('pending');
        encIndicator.querySelector('span').textContent = label;
    }
}

// ── chat navigation ───────────────────────────────────────────────────────────
function selectChat(peerId) {
    activePeerId = peerId;
    const p = peers.get(peerId);

    unreadCounts.set(peerId, 0);

    noChatEl.classList.add('hidden');
    activeChatEl.classList.remove('hidden');
    appWrapper.classList.add('mobile-chat-active');

    chatNameEl.textContent = p.name;
    chatAvatarEl.src = p.avatar;
    chatStatusEl.textContent = p.status;

    updateEncIndicator(p.e2eReady, peerId);

    renderContactsList();
    renderMessages();
    messageInput.focus();
}

// ── send ──────────────────────────────────────────────────────────────────────
async function sendMessage() {
    const text = messageInput.value.trim();
    if (!text || !activePeerId) return;

    try {
        await invoke('send_p2p_message', { to: activePeerId, content: text });

        const t = timeStr();
        const ts = Date.now();
        if (!messages.has(activePeerId)) messages.set(activePeerId, []);
        messages.get(activePeerId).push({ text, sent: true, time: t, nick: myNickname, ts });

        const p = peers.get(activePeerId);
        if (p) { p.lastMsg = text; p.lastTime = t; }

        messageInput.value = '';
        renderMessages();
        renderContactsList();
        saveState();
    } catch (e) {
        console.error('send failed', e);
        alert('Failed to send: ' + e);
    }
}

// ── utils ─────────────────────────────────────────────────────────────────────
function escHtml(str) {
    const d = document.createElement('div');
    d.textContent = str;
    return d.innerHTML;
}

// ── modal logic ───────────────────────────────────────────────────────────────

// nickname first-run
confirmNick.onclick = async () => {
    const name = nicknameInput.value.trim();
    if (!name) return;
    await invoke('set_nickname', { name });
    applyNickname(name);
    nicknameModal.classList.add('hidden');
    saveState();
};

nicknameInput.onkeydown = (e) => { if (e.key === 'Enter') confirmNick.click(); };

// edit nickname
editNickBtn.onclick = () => {
    editNickInput.value = myNickname;
    editNickModal.classList.remove('hidden');
    editNickInput.focus();
};

cancelEditNick.onclick = () => editNickModal.classList.add('hidden');

confirmEditNick.onclick = async () => {
    const name = editNickInput.value.trim();
    if (!name) return;
    await invoke('set_nickname', { name });
    applyNickname(name);
    editNickModal.classList.add('hidden');
    saveState();
};

editNickInput.onkeydown = (e) => { if (e.key === 'Enter') confirmEditNick.click(); };

// add friend
addFriendBtn.onclick = () => {
    friendIdInput.value = '';
    addFriendModal.classList.remove('hidden');
    friendIdInput.focus();
};

cancelModal.onclick = () => addFriendModal.classList.add('hidden');

confirmAddFriend.onclick = async () => {
    const input = friendIdInput.value.trim();
    if (!input) return;

    let id = input;
    let isMultiaddr = input.includes('/p2p/');

    if (isMultiaddr) {
        // extract peer id from multiaddr
        const parts = input.split('/p2p/');
        id = parts[parts.length - 1];
    }

    // add to local contacts immediately with a connecting status
    onPeerDiscovered(id, '');
    const p = peers.get(id);
    if (p) {
        p.status = 'connecting';
        p.lastMsg = 'searching via internet...';
        
        // set 30s timeout for "connecting" state
        if (p.connTimeout) clearTimeout(p.connTimeout);
        p.connTimeout = setTimeout(() => {
            const peer = peers.get(id);
            if (peer && peer.status === 'connecting') {
                peer.status = 'offline';
                peer.lastMsg = 'peer not found / offline';
                renderContactsList();
                if (activePeerId === id) chatStatusEl.textContent = 'offline';
                saveState();
            }
        }, 30000);
        
        peers.set(id, p);
    }
    addFriendModal.classList.add('hidden');
    selectChat(id);

    // tell the backend to initiate key exchange or dial
    try {
        if (isMultiaddr) {
            await invoke('dial_address', { address: input });
        } else {
            await invoke('dial_peer', { peer_id: id });
        }
    } catch (e) {
        console.error('dial failed', e);
        if (p) {
            p.status = 'offline';
            p.lastMsg = 'dial failed: ' + e;
            renderContactsList();
        }
    }
    saveState();
};

friendIdInput.onkeydown = (e) => { if (e.key === 'Enter') confirmAddFriend.click(); };

// bootstrap network
if (confirmBootstrap) {
    confirmBootstrap.onclick = async () => {
        const addr = bootstrapInput.value.trim();
        if (!addr) return;
        try {
            await invoke('bootstrap', { address: addr });
            alert('Bootstrap initiated. Joining network...');
            bootstrapInput.value = '';
            addFriendModal.classList.add('hidden');
        } catch (e) {
            console.error('bootstrap failed', e);
            alert('Bootstrap failed: ' + e);
        }
    };
}

// qr code
myAvatarWrap.onclick = () => {
    if (!myPeerId) return;
    qrPeerIdEl.textContent = myPeerId;
    document.getElementById('qrcode').innerHTML = '';
    qrInstance = new QRCode(document.getElementById('qrcode'), {
        text: myPeerId,
        width: 220,
        height: 220,
        colorDark: '#00d4ff',
        colorLight: '#ffffff',
        correctLevel: QRCode.CorrectLevel.H,
    });
    qrModal.classList.remove('hidden');
};

closeQrModal.onclick = () => qrModal.classList.add('hidden');

// close modals by clicking backdrop
[nicknameModal, editNickModal, addFriendModal, qrModal].forEach(modal => {
    modal.addEventListener('click', (e) => {
        if (e.target === modal && modal !== nicknameModal) {
            modal.classList.add('hidden');
        }
    });
});

// back button (mobile)
backBtn.onclick = () => appWrapper.classList.remove('mobile-chat-active');

// send button + enter
sendBtn.onclick = sendMessage;
messageInput.onkeydown = (e) => { if (e.key === 'Enter') sendMessage(); };

// search
searchInput.oninput = (e) => {
    searchQuery = e.target.value;
    renderContactsList();
};

// ── qr scanner ───────────────────────────────────────────────────────────────
async function stopQrScanner() {
    if (html5QrScanner) {
        try {
            if (html5QrScanner.isScanning) {
                await html5QrScanner.stop();
            }
            html5QrScanner.clear();
        } catch (e) {
            console.warn('error stopping scanner', e);
        }
        html5QrScanner = null;
    }
}

if (scanQrBtn) {
    scanQrBtn.onclick = () => {
        addFriendModal.classList.add('hidden');
        qrScannerModal.classList.remove('hidden');

        html5QrScanner = new Html5Qrcode('qr-reader');
        html5QrScanner.start(
            { facingMode: 'environment' },
            { fps: 10, qrbox: { width: 250, height: 250 } },
            async (decodedText) => {
                // got a scan result — fill the add friend input and switch back
                await stopQrScanner();
                qrScannerModal.classList.add('hidden');
                friendIdInput.value = decodedText;
                addFriendModal.classList.remove('hidden');
            },
            () => { } // ignore scan errors
        ).catch(async (err) => {
            console.error('camera error', err);
            await stopQrScanner();
            qrScannerModal.classList.add('hidden');
            alert('Could not access camera: ' + err);
        });
    };
}

if (closeScannerModal) {
    closeScannerModal.onclick = async () => {
        await stopQrScanner();
        qrScannerModal.classList.add('hidden');
    };
}

// close scanner modal on backdrop click
if (qrScannerModal) {
    qrScannerModal.addEventListener('click', async (e) => {
        if (e.target === qrScannerModal) {
            await stopQrScanner();
            qrScannerModal.classList.add('hidden');
        }
    });
}

// ── settings logic ───────────────────────────────────────────────────────────
if (settingsBtn) {
    settingsBtn.onclick = () => settingsModal.classList.remove('hidden');
}

if (closeSettingsBtn) {
    closeSettingsBtn.onclick = () => settingsModal.classList.add('hidden');
}

if (settingsModal) {
    settingsModal.addEventListener('click', (e) => {
        if (e.target === settingsModal) settingsModal.classList.add('hidden');
    });
}

if (resetAppBtn) {
    resetAppBtn.onclick = async () => {
        const confirmed = confirm("Are you ABSOLUTELY sure? This will delete all messages, contacts, and your Peer ID identity. The app will restart.");
        if (confirmed) {
            try {
                // 1. Clear store
                await store.clear();
                await store.save();

                // 2. Remove identity key on backend
                await invoke('reset_identity');

                // 3. Restart app
                window.location.reload();
            } catch (e) {
                console.error('reset failed', e);
                alert('Reset failed: ' + e);
            }
        }
    };
}

// ── boot ──────────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
    console.log('dom ready');
    if (window.__TAURI__) {
        init();
    } else {
        console.error('tauri not found — browser mode may have limited functionality');
        // show nickname modal in browser preview too
        nicknameModal.classList.remove('hidden');
        myPeerIdEl.textContent = 'browser-preview';
    }
});
