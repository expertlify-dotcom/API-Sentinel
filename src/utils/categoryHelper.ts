export type CategoryKey = 'client_ide' | 'firebase' | 'aws' | 'ai' | 'other';

export interface CategorySpec {
  key: CategoryKey;
  label: string;
  color: string;
  bgDark: string;
  desc: string;
  borderColor: string;
}

export const PARENT_CATEGORIES: Record<CategoryKey, CategorySpec> = {
  client_ide: {
    key: 'client_ide',
    label: 'Client / IDE API',
    color: 'text-emerald-700 bg-emerald-50 border-emerald-200',
    bgDark: 'bg-emerald-950/20 border-emerald-500/20 text-emerald-300',
    desc: 'Public maps, SDK tokens, client browser configurations, or developer IDE integrations',
    borderColor: 'border-emerald-200'
  },
  firebase: {
    key: 'firebase',
    label: 'Backend Firebase API',
    color: 'text-orange-700 bg-orange-50 border-orange-200',
    bgDark: 'bg-orange-950/20 border-orange-500/20 text-orange-300',
    desc: 'Firebase/Firestore configurations, server-side GCP permissions, or cloud data gatekeepers',
    borderColor: 'border-orange-200'
  },
  aws: {
    key: 'aws',
    label: 'AWS API',
    color: 'text-amber-700 bg-amber-50 border-amber-200',
    bgDark: 'bg-amber-950/20 border-amber-500/20 text-amber-305',
    desc: 'Amazon Web Services IAM user keys, private bucket secrets, or server roles',
    borderColor: 'border-amber-200'
  },
  ai: {
    key: 'ai',
    label: 'AI Generative API',
    color: 'text-indigo-705 bg-indigo-50 border-indigo-200',
    bgDark: 'bg-indigo-950/20 border-indigo-500/20 text-indigo-300',
    desc: 'Generative models endpoints, such as Google Gemini developer keys, OpenAI tokens, or Claude private credentials',
    borderColor: 'border-indigo-200'
  },
  other: {
    key: 'other',
    label: 'All other APIs',
    color: 'text-slate-700 bg-slate-50 border-slate-205',
    bgDark: 'bg-slate-900/40 border-slate-700/60 text-slate-300',
    desc: 'Stripe payments keys, Slack webhooks, database connection strings, or custom internal integrations',
    borderColor: 'border-slate-200'
  }
};

/**
 * Returns the parent category key for any given finding context
 */
export function getParentCategory(categoryStr: string, title?: string, evidence?: string): CategoryKey {
  const normCategory = (categoryStr || '').toLowerCase();
  const normTitle = (title || '').toLowerCase();
  const normEvidence = (evidence || '').toLowerCase();
  
  const combined = `${normCategory} ${normTitle} ${normEvidence}`;

  // Check Backend Firebase
  if (
    combined.includes('firebase') || 
    combined.includes('firestore') || 
    combined.includes('firebaseapp')
  ) {
    return 'firebase';
  }

  // Check AWS
  if (
    combined.includes('aws') || 
    combined.includes('amazon') || 
    combined.includes('s3') || 
    combined.includes('iam') || 
    combined.includes('akia') || 
    combined.includes('asca')
  ) {
    return 'aws';
  }

  // Check AI Generative API
  if (
    combined.includes('gemini') || 
    combined.includes('openai') || 
    combined.includes('anthropic') || 
    combined.includes('claude') || 
    textIsAi(normTitle, normCategory, normEvidence)
  ) {
    return 'ai';
  }

  // Check Client / IDE API
  if (
    combined.includes('maps') || 
    combined.includes('google maps') || 
    combined.includes('google cloud / maps platform') || 
    combined.includes('client api') || 
    combined.includes('ide api') || 
    combined.includes('ide') || 
    combined.includes('browser') || 
    combined.includes('replit') || 
    combined.includes('vscode') || 
    combined.includes('coder') ||
    combined.includes('frontend') ||
    combined.includes('client-side')
  ) {
    return 'client_ide';
  }

  // Fallback for AI keys such as general Google AI developer API keys
  if (combined.includes('google-service') || combined.includes('services.google')) {
    return 'firebase';
  }

  return 'other';
}

function textIsAi(title: string, cat: string, evidence: string): boolean {
  const t = `${title} ${cat} ${evidence}`.toLowerCase();
  return (
    t.includes('generativeai') || 
    t.includes('generative api') || 
    t.includes('deepseek') || 
    t.includes('llama') ||
    t.includes('cohere') ||
    t.includes('huggingface') ||
    t.includes('groq') ||
    t.includes('mistral') ||
    t.includes('gpt-') ||
    t.includes('chatgpt')
  );
}
