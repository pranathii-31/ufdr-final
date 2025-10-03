import React, { createContext, useState, useContext } from 'react';

const translations = {
  en: {
    appName: 'FORENSEEK',
    search: 'Search',
    login: 'Login',
    signup: 'Sign Up',
    logout: 'Logout',
    email: 'Email',
    password: 'Password',
    name: 'Name',
    searchPlaceholder: 'Search forensic data...',
    results: 'Results',
    filters: 'Filters',
    profile: 'Profile',
    notifications: 'Notifications',
    analytics: 'Analytics',
    auditLogs: 'Audit Logs',
    upload: 'Upload',
    export: 'Export PDF',
    rebuildIndex: 'Rebuild Index',
    textToSpeech: 'Text to Speech',
    collaborate: 'Collaborate',
    advancedFilters: 'Advanced Filters',
    dateRange: 'Date Range',
    relevance: 'Relevance',
    caseType: 'Case Type'
  },
  es: {
    appName: 'FORENSEEK',
    search: 'Buscar',
    login: 'Iniciar sesión',
    signup: 'Registrarse',
    logout: 'Cerrar sesión',
    email: 'Correo electrónico',
    password: 'Contraseña',
    name: 'Nombre',
    searchPlaceholder: 'Buscar datos forenses...',
    results: 'Resultados',
    filters: 'Filtros',
    profile: 'Perfil',
    notifications: 'Notificaciones',
    analytics: 'Analítica',
    auditLogs: 'Registros de auditoría',
    upload: 'Subir',
    export: 'Exportar PDF',
    rebuildIndex: 'Reconstruir índice',
    textToSpeech: 'Texto a voz',
    collaborate: 'Colaborar',
    advancedFilters: 'Filtros avanzados',
    dateRange: 'Rango de fechas',
    relevance: 'Relevancia',
    caseType: 'Tipo de caso'
  },
  fr: {
    appName: 'FORENSEEK',
    search: 'Rechercher',
    login: 'Connexion',
    signup: "S'inscrire",
    logout: 'Déconnexion',
    email: 'E-mail',
    password: 'Mot de passe',
    name: 'Nom',
    searchPlaceholder: 'Rechercher des données forensiques...',
    results: 'Résultats',
    filters: 'Filtres',
    profile: 'Profil',
    notifications: 'Notifications',
    analytics: 'Analytique',
    auditLogs: "Journaux d'audit",
    upload: 'Télécharger',
    export: 'Exporter PDF',
    rebuildIndex: "Reconstruire l'index",
    textToSpeech: 'Synthèse vocale',
    collaborate: 'Collaborer',
    advancedFilters: 'Filtres avancés',
    dateRange: 'Plage de dates',
    relevance: 'Pertinence',
    caseType: 'Type de cas'
  }
};

export const LanguageContext = createContext();

export const LanguageProvider = ({ children }) => {
  const [language, setLanguage] = useState('en');

  const value = {
    language,
    setLanguage,
    translations: translations[language]
  };

  return (
    <LanguageContext.Provider value={value}>
      {children}
    </LanguageContext.Provider>
  );
};

export const useLanguage = () => {
  const context = useContext(LanguageContext);
  if (context === undefined) {
    throw new Error('useLanguage must be used within a LanguageProvider');
  }
  return context;
};