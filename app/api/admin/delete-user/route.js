import jwt from 'jsonwebtoken';
import { NextResponse } from 'next/server';
import { getUserFromDB, deleteUserFromDB } from '../../../../utils/authHelpers';

// Validate JWT secret configuration
function validateJWTSecret() {
  const secret = process.env.JWT_SECRET;
  
  if (!secret) {
    throw new Error('JWT_SECRET environment variable is not configured');
  }
  
  if (secret.length < 32) {
    throw new Error('JWT_SECRET must be at least 32 characters long');
  }
  
  // Check for common weak secrets
  const weakSecrets = [
    'secret',
    'password',
    'jwt_secret',
    'your-secret-key-here',
    '123456',
    'test',
    'development'
  ];
  
  if (weakSecrets.includes(secret.toLowerCase())) {
    throw new Error('JWT_SECRET is using a weak or default value');
  }
  
  return secret;
}

export async function POST(request) {
  try {
    // Validate JWT secret before proceeding
    const jwtSecret = validateJWTSecret();
    
    // Check for CSRF token in headers
    const csrfToken = request.headers.get('x-csrf-token');
    if (!csrfToken || csrfToken !== process.env.CSRF_TOKEN) {
      return NextResponse.json(
        { error: 'CSRF token missing or invalid' },
        { status: 403 }
      );
    }

    const formData = await request.formData();
    const userId = formData.get('userId');
    
    const authCookie = request.cookies.get('auth')?.value;
    if (!authCookie) {
      return NextResponse.json(
        { error: 'Unauthorized' }, 
        { status: 401 }
      );
    }

    // Use validated secret for JWT verification
    const decoded = jwt.verify(authCookie, jwtSecret);
    const adminUser = await getUserFromDB(decoded.userId);
    
    if (!adminUser.isAdmin) {
      return NextResponse.json(
        { error: 'Admin required' }, 
        { status: 403 }
      );
    }

    await deleteUserFromDB(userId);
    
    return NextResponse.json({ success: true });
  } catch (error) {
    // Log security-related errors for monitoring
    if (error.message.includes('JWT_SECRET')) {
      console.error('JWT configuration error:', error.message);
      return NextResponse.json(
        { error: 'Server configuration error' }, 
        { status: 500 }
      );
    }
    
    return NextResponse.json(
      { error: 'Invalid token' }, 
      { status: 401 }
    );
  }
}