/**
 * PROTECTION DE LA CONSOLE
 * Empêche l'accès à la console JavaScript pour prévenir les attaques
 * et l'injection de code malveillant
 */

(function() {
    'use strict';

    // Désactiver la console en production
    if (window.location.hostname !== 'localhost' && window.location.hostname !== '127.0.0.1') {
        // Sauvegarder les fonctions originales
        const noop = function() {};
        const consoleMethods = [
            'log', 'debug', 'info', 'warn', 'error', 'table',
            'trace', 'dir', 'group', 'groupEnd', 'time', 'timeEnd',
            'profile', 'profileEnd', 'clear'
        ];

        // Désactiver toutes les méthodes de la console
        consoleMethods.forEach(method => {
            if (window.console && window.console[method]) {
                window.console[method] = noop;
            }
        });

        // Empêcher l'ouverture des DevTools
        const devtools = /./;
        devtools.toString = function() {
            this.opened = true;
            return 'AVERTISSEMENT: L\'utilisation de la console est désactivée pour des raisons de sécurité.';
        };

        // Vérification périodique de l'ouverture des DevTools
        setInterval(() => {
            if (devtools.opened) {
                window.location.reload();
            }
        }, 1000);
        
        // Détecter les debuggers (only in non-localhost environments)
        setInterval(() => {
            const before = new Date();
            debugger;
            const after = new Date();
            if (after - before > 100) {
                // Debugger détecté
                window.location.reload();
            }
        }, 1000);
    }

    // Désactiver le clic droit (optionnel, peut être gênant pour les utilisateurs)
    // document.addEventListener('contextmenu', event => event.preventDefault());

    // Désactiver certaines combinaisons de touches
    document.addEventListener('keydown', (event) => {
        // F12 - DevTools
        if (event.keyCode === 123) {
            event.preventDefault();
            return false;
        }

        // Ctrl+Shift+I - DevTools
        if (event.ctrlKey && event.shiftKey && event.keyCode === 73) {
            event.preventDefault();
            return false;
        }

        // Ctrl+Shift+J - Console
        if (event.ctrlKey && event.shiftKey && event.keyCode === 74) {
            event.preventDefault();
            return false;
        }

        // Ctrl+U - View Source
        if (event.ctrlKey && event.keyCode === 85) {
            event.preventDefault();
            return false;
        }

        // Ctrl+Shift+C - Inspect Element
        if (event.ctrlKey && event.shiftKey && event.keyCode === 67) {
            event.preventDefault();
            return false;
        }
    });

    // Protection contre la modification du DOM via la console
    // Avoid freezing host objects like `window` or `document` - freezing can cause
    // runtime TypeErrors in some browsers. We keep other protections but don't freeze.

    // NOTE: debugger-detection runs only in the block above for non-localhost.

    // Message d'avertissement personnalisé
    console.log('%c⚠️ AVERTISSEMENT DE SÉCURITÉ', 'color: red; font-size: 40px; font-weight: bold;');
    console.log('%cCette fonction du navigateur est destinée aux développeurs.', 'font-size: 16px;');
    console.log('%cSi quelqu\'un vous a demandé de copier-coller quelque chose ici, il s\'agit probablement d\'une tentative de piratage.', 'font-size: 16px;');
    console.log('%cL\'exécution de code non autorisé peut compromettre votre compte et vos données.', 'font-size: 16px; color: red;');

    // Protection contre eval() et Function()
    window.eval = function() {
        throw new Error('eval() est désactivé pour des raisons de sécurité');
    };

    const OriginalFunction = Function;
    window.Function = function() {
        throw new Error('Function() est désactivé pour des raisons de sécurité');
    };

})();
