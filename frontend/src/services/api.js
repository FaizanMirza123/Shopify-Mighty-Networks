const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Helper function to get auth headers
const getAuthHeaders = () => {
  const token = localStorage.getItem('access_token');
  return {
    'Content-Type': 'application/json',
    ...(token ? { 'Authorization': `Bearer ${token}` } : {}),
  };
};

// Helper function to handle unauthorized responses
const handleResponse = async (response) => {
  if (response.status === 401) {
    // Token expired or invalid, redirect to login
    localStorage.removeItem('user');
    localStorage.removeItem('access_token');
    window.location.href = '/login';
    throw new Error('Session expired. Please login again.');
  }
  
  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Request failed' }));
    throw new Error(error.detail || 'Request failed');
  }
  
  return response.json();
};

export const api = {
  // Auth endpoints
  login: async (email, password) => {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    });
    
    return handleResponse(response);
  },

  // User Plans endpoints
  getUserPlans: async (userId) => {
    const response = await fetch(`${API_BASE_URL}/users/${userId}/plans`, {
      headers: getAuthHeaders(),
    });
    
    return handleResponse(response);
  },

  // Invites endpoints
  sendInvite: async (userId, userPlanId, email, firstName = '', lastName = '') => {
    const response = await fetch(`${API_BASE_URL}/users/${userId}/plans/${userPlanId}/invite`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        email,
        first_name: firstName,
        last_name: lastName,
      }),
    });
    
    return handleResponse(response);
  },

  getUserInvites: async (userId) => {
    const response = await fetch(`${API_BASE_URL}/users/${userId}/invites`, {
      headers: getAuthHeaders(),
    });
    
    return handleResponse(response);
  },

  revokeInvite: async (userId, inviteId) => {
    const response = await fetch(`${API_BASE_URL}/users/${userId}/invites/${inviteId}`, {
      method: 'DELETE',
      headers: getAuthHeaders(),
    });
    
    return handleResponse(response);
  },
};
