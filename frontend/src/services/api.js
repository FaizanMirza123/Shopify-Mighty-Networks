const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

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
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Login failed');
    }
    
    return response.json();
  },

  // User Plans endpoints
  getUserPlans: async (userId) => {
    const response = await fetch(`${API_BASE_URL}/users/${userId}/plans`);
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to fetch plans');
    }
    
    return response.json();
  },

  // Invites endpoints
  sendInvite: async (userId, userPlanId, email, firstName = '', lastName = '') => {
    const response = await fetch(`${API_BASE_URL}/users/${userId}/plans/${userPlanId}/invite`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email,
        first_name: firstName,
        last_name: lastName,
      }),
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to send invite');
    }
    
    return response.json();
  },

  revokeInvite: async (userId, inviteId) => {
    const response = await fetch(`${API_BASE_URL}/users/${userId}/invites/${inviteId}`, {
      method: 'DELETE',
    });
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to revoke invite');
    }
    
    return response.json();
  },

  getUserInvites: async (userId) => {
    const response = await fetch(`${API_BASE_URL}/users/${userId}/invites`);
    
    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.detail || 'Failed to fetch invites');
    }
    
    return response.json();
  },
};
