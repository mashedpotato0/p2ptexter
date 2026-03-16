const { listen } = window.__TAURI__.event;
const { invoke } = window.__TAURI__.core;

// state management
let myPeerId = null;
let activeChatPeerId = null;
let peers = new Map(); // peer id to metadata
let messagesByPeer = new Map(); // messages grouped by peer

// dom elements
const myPeerIdEl = document.getElementById('my-peer-id');
const contactsListEl = document.getElementById('contacts-list');
const activeChatEl = document.getElementById('active-chat');
const noChatEl = document.getElementById('no-chat-selected');
const messageListEl = document.getElementById('message-list');
const messageInput = document.getElementById('message-input');
const sendBtn = document.getElementById('send-btn');
const chatNameEl = document.getElementById('chat-name');
const chatAvatarEl = document.getElementById('chat-avatar');
const backBtn = document.getElementById('back-btn');
const appWrapper = document.querySelector('.app-wrapper');

// modal elements
const addFriendBtn = document.getElementById('add-friend-btn');
const addFriendModal = document.getElementById('add-friend-modal');
const friendIdInput = document.getElementById('friend-id-input');
const confirmAddFriend = document.getElementById('confirm-add-friend');
const cancelModal = document.getElementById('cancel-modal');

const closeQrModal = document.getElementById('close-qr-modal');
const qrPeerIdDisplay = document.getElementById('qr-peer-id');
let qrCodeInstance = null;

// qr code stuff
const myAvatar = document.querySelector('.sidebar-header .avatar');
const qrModal = document.getElementById('qr-modal');

// start things up
async function init() {
    console.log('initializing js');

    // listen for p2p events
    await listen('p2p-event', (event) => {
        const payload = event.payload;
        console.log('got p2p event', payload);

        if (payload.event_type === 'MessageReceived') {
            handleIncomingMessage(payload.peer_id, payload.content);
        } else if (payload.event_type === 'PeerDiscovered') {
            handlePeerDiscovered(payload.peer_id);
        } else if (payload.event_type === 'PeerExpired') {
            handlePeerExpired(payload.peer_id);
        } else if (payload.event_type === 'ListenAddress') {
            // handle address if we need to
        }
    });

    // get our identity
    try {
        console.log('fetching peer id');
        myPeerId = await invoke('get_my_peer_id');
        console.log('got my id', myPeerId);
        if (myPeerId) {
            myPeerIdEl.textContent = myPeerId;
        }
    } catch (e) {
        console.error('failed to get id', e);
        myPeerIdEl.textContent = "Error: " + e;
    }
}

function handlePeerDiscovered(peerId) {
    if (!peers.has(peerId)) {
        peers.set(peerId, {
            name: `Peer ${peerId.substring(0, 6)}`,
            status: 'online',
            lastMessage: 'Just joined the network',
            avatar: `https://api.dicebear.com/7.x/bottts/svg?seed=${peerId}`
        });
        renderContactsList();
    }
}

function handlePeerExpired(peerId) {
    if (peers.has(peerId)) {
        const peer = peers.get(peerId);
        peer.status = 'offline';
        renderContactsList();
    }
}

function handleIncomingMessage(peerId, content) {
    const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    if (!messagesByPeer.has(peerId)) {
        messagesByPeer.set(peerId, []);
    }

    const msg = { text: content, sent: false, time };
    messagesByPeer.get(peerId).push(msg);

    // save last message info
    if (peers.has(peerId)) {
        peers.get(peerId).lastMessage = content;
        peers.get(peerId).status = 'online';
    } else {
        // new peer found via message
        handlePeerDiscovered(peerId);
        peers.get(peerId).lastMessage = content;
    }

    renderContactsList();

    if (activeChatPeerId === peerId) {
        renderMessages();
    }
}

function renderContactsList() {
    contactsListEl.innerHTML = '';
    peers.forEach((peer, id) => {
        const item = document.createElement('div');
        item.className = `contact-item ${activeChatPeerId === id ? 'active' : ''}`;
        item.innerHTML = `
            <img src="${peer.avatar}" class="avatar">
            <div class="contact-info-text">
                <div class="contact-name-row">
                    <span class="contact-name">${peer.name}</span>
                    <span class="last-time">${peer.status}</span>
                </div>
                <span class="last-msg">${peer.lastMessage}</span>
            </div>
        `;
        item.onclick = () => selectChat(id);
        contactsListEl.appendChild(item);
    });
}

function selectChat(peerId) {
    activeChatPeerId = peerId;
    const peer = peers.get(peerId);

    noChatEl.classList.add('hidden');
    activeChatEl.classList.remove('hidden');

    chatNameEl.textContent = peer.name;
    chatAvatarEl.src = peer.avatar;

    // slide into chat view on mobile
    appWrapper.classList.add('mobile-chat-active');

    renderContactsList();
    renderMessages();
}

function renderMessages() {
    messageListEl.innerHTML = '';
    const messages = messagesByPeer.get(activeChatPeerId) || [];

    messages.forEach(msg => {
        const msgEl = document.createElement('div');
        msgEl.className = `message ${msg.sent ? 'sent' : 'received'}`;
        msgEl.innerHTML = `
            ${msg.text}
            <span class="message-time">${msg.time}</span>
        `;
        messageListEl.appendChild(msgEl);
    });

    messageListEl.scrollTop = messageListEl.scrollHeight;
}

// user actions
async function sendMessage() {
    const text = messageInput.value.trim();
    if (!text || !activeChatPeerId) return;

    try {
        await invoke('send_p2p_message', { content: text }); // backend just broadcasts for now

        const time = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        if (!messagesByPeer.has(activeChatPeerId)) {
            messagesByPeer.set(activeChatPeerId, []);
        }

        messagesByPeer.get(activeChatPeerId).push({ text, sent: true, time });

        if (peers.has(activeChatPeerId)) {
            peers.get(activeChatPeerId).lastMessage = text;
        }

        messageInput.value = '';
        renderMessages();
        renderContactsList();
    } catch (e) {
        alert('Failed to send message: ' + e);
    }
}

// modal logic
addFriendBtn.onclick = () => addFriendModal.classList.remove('hidden');
cancelModal.onclick = () => addFriendModal.classList.add('hidden');

confirmAddFriend.onclick = () => {
    const id = friendIdInput.value.trim();
    if (id) {
        handlePeerDiscovered(id);
        addFriendModal.classList.add('hidden');
        friendIdInput.value = '';
        selectChat(id);
    }
};

// qr code logic
myAvatar.onclick = () => {
    if (!myPeerId) return;

    qrPeerIdDisplay.textContent = myPeerId;
    qrModal.classList.remove('hidden');

    // wipe old qr
    document.getElementById('qrcode').innerHTML = "";

    // generate fresh qr code
    qrCodeInstance = new QRCode(document.getElementById("qrcode"), {
        text: myPeerId,
        width: 256,
        height: 256,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.H
    });
};

closeQrModal.onclick = () => {
    qrModal.classList.add('hidden');
};

backBtn.onclick = () => {
    appWrapper.classList.remove('mobile-chat-active');
};

sendBtn.onclick = sendMessage;
messageInput.onkeypress = (e) => {
    if (e.key === 'Enter') sendMessage();
};

// wait for dom then start
window.addEventListener('DOMContentLoaded', () => {
    console.log('dom is ready');
    // make sure tauri is there
    if (window.__TAURI__) {
        init();
    } else {
        console.error('tauri missing maybe browser mode');
    }
});
