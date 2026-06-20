import api from './api'

export const getDashboardSummary = () => api.get('/dashboard/summary')
export const getTopFindings      = () => api.get('/dashboard/top-findings')
