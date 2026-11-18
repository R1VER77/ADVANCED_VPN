import { createApp } from 'vue'
import './style.css'
// A separate Vite entry keeps demonstration controllers and PIN simulations out
// of production. Service failure never loads a mock implementation.
import App from './App.vue'
createApp(App).mount('#app')
