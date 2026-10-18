import {defineConfig} from 'vite';
export default defineConfig({
 base:'./',
 build:{outDir:'../../dist/real',emptyOutDir:true},
 server:{port:4788,strictPort:true}
});
