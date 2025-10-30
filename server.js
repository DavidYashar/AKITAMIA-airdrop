// Express server to save signed claims to PostgreSQL
require('dotenv').config(); // Load environment variables

const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3001;

// Trust proxy for correct IP detection on Render/production
app.set('trust proxy', true);

// CORS configuration with environment-based origins
const allowedOrigins = process.env.ALLOWED_ORIGINS 
    ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
    : '*';

app.use(cors({
    origin: allowedOrigins,
    credentials: true
}));

app.use(express.json({ limit: '1mb' })); // Reduced from 10mb to prevent DoS attacks

// Simple rate limiting: Track requests per IP
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 60 * 60 * 1000; // 1 hour in milliseconds
const RATE_LIMIT_MAX_REQUESTS = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 10000; // Max requests per IP per hour

function checkRateLimit(ip) {
    const now = Date.now();
    const userRequests = rateLimitMap.get(ip) || [];
    
    // Remove old requests outside the time window
    const recentRequests = userRequests.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
    
    if (recentRequests.length >= RATE_LIMIT_MAX_REQUESTS) {
        return false; // Rate limit exceeded
    }
    
    // Add current request
    recentRequests.push(now);
    rateLimitMap.set(ip, recentRequests);
    
    return true; // Request allowed
}

// Clean up old rate limit data every hour
setInterval(() => {
    const now = Date.now();
    for (const [ip, timestamps] of rateLimitMap.entries()) {
        const recentRequests = timestamps.filter(timestamp => now - timestamp < RATE_LIMIT_WINDOW);
        if (recentRequests.length === 0) {
            rateLimitMap.delete(ip);
        } else {
            rateLimitMap.set(ip, recentRequests);
        }
    }
}, RATE_LIMIT_WINDOW);

// PostgreSQL connection using environment variables
const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'akitamia_airdrop',
    password: process.env.DB_PASSWORD,
    port: parseInt(process.env.DB_PORT) || 5432,
});

// Test database connection and create tables if needed
pool.query('SELECT NOW()', async (err, res) => {
    if (err) {
        console.error('❌ Database connection failed:', err.message);
        console.log('💡 Make sure PostgreSQL is running and database exists');
    } else {
        console.log('✅ Database connected successfully');
        
        // Create tables if they don't exist
        try {
            await pool.query(`
                CREATE TABLE IF NOT EXISTS claims (
                    id SERIAL PRIMARY KEY,
                    claim_id TEXT UNIQUE NOT NULL,
                    spark_address TEXT UNIQUE NOT NULL,
                    total_akitamia INTEGER NOT NULL,
                    wallet_type TEXT NOT NULL,
                    signed_by_wallet TEXT NOT NULL,
                    signed_at TIMESTAMP NOT NULL,
                    saved_at TIMESTAMP DEFAULT NOW(),
                    raw_signature JSONB,
                    created_at TIMESTAMP DEFAULT NOW()
                );
                
                CREATE TABLE IF NOT EXISTS wallets (
                    id SERIAL PRIMARY KEY,
                    claim_id TEXT NOT NULL,
                    btc_address TEXT NOT NULL,
                    akitamia_count INTEGER NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    UNIQUE(claim_id, btc_address)
                );
                
                CREATE TABLE IF NOT EXISTS claim_data (
                    id SERIAL PRIMARY KEY,
                    claim_id TEXT UNIQUE NOT NULL,
                    full_json JSONB NOT NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
                
                CREATE INDEX IF NOT EXISTS idx_claims_spark_address ON claims(spark_address);
                CREATE INDEX IF NOT EXISTS idx_claims_claim_id ON claims(claim_id);
                CREATE INDEX IF NOT EXISTS idx_wallets_claim_id ON wallets(claim_id);
                CREATE INDEX IF NOT EXISTS idx_wallets_btc_address ON wallets(btc_address);
            `);
            
            console.log('✅ Database tables ready');
        } catch (tableError) {
            console.error('⚠️ Error creating tables:', tableError.message);
        }
    }
});

// Validation Functions

// Check if string contains only alphanumeric characters (security: prevent injection)
function isAlphanumericOnly(str) {
    return /^[a-zA-Z0-9]+$/.test(str);
}

function validateSparkAddress(sparkAddress) {
    if (!sparkAddress || typeof sparkAddress !== 'string') {
        return { valid: false, error: 'Spark address is required' };
    }
    
    // SECURITY: Check for alphanumeric only (prevent XSS, SQL injection, code injection)
    if (!isAlphanumericOnly(sparkAddress)) {
        return { 
            valid: false, 
            error: 'Invalid characters detected. Spark address must contain only letters and numbers.' 
        };
    }
    
    // Simple validation: Just check if it starts with sp1, spark1, or SP (mainnet)
    // The rest is user's responsibility
    const startsWithSp1 = sparkAddress.startsWith('sp1');
    const startsWithSpark1 = sparkAddress.startsWith('spark1');
    const startsWithSP = sparkAddress.startsWith('SP');
    
    if (!startsWithSp1 && !startsWithSpark1 && !startsWithSP) {
        return { 
            valid: false, 
            error: 'Invalid Spark address. Must start with sp1, spark1, or SP (mainnet only)' 
        };
    }
    
    // Reject testnet addresses
    if (sparkAddress.startsWith('ST') || sparkAddress.startsWith('st1')) {
        return { 
            valid: false, 
            error: 'Testnet addresses (ST, st1) are not allowed. Use mainnet address only.' 
        };
    }
    
    // Basic length check (should be at least 10 characters)
    if (sparkAddress.length < 10) {
        return { 
            valid: false, 
            error: 'Spark address is too short' 
        };
    }
    
    return { valid: true };
}

function validateBitcoinAddress(address) {
    if (!address || typeof address !== 'string') {
        return { valid: false, error: 'Bitcoin address is required' };
    }
    
    // SECURITY: Check for alphanumeric only (prevent XSS, SQL injection, code injection)
    if (!isAlphanumericOnly(address)) {
        return { 
            valid: false, 
            error: 'Invalid characters detected. Bitcoin address must contain only letters and numbers.' 
        };
    }
    
    // Check for Taproot (bc1p) or SegWit (bc1q) addresses
    const btcRegex = /^(bc1p|bc1q)[a-z0-9]{39,87}$/;
    
    if (!btcRegex.test(address)) {
        return { valid: false, error: 'Invalid Bitcoin address format. Must be bc1p (Taproot) or bc1q (SegWit)' };
    }
    
    return { valid: true };
}

function validateSignature(signature) {
    if (!signature || typeof signature !== 'string') {
        return { valid: false, error: 'Signature is required' };
    }
    
    // Check if signature is not empty and has reasonable length
    if (signature.length < 50) {
        return { valid: false, error: 'Signature appears to be invalid (too short)' };
    }
    
    // Basic check - signature should contain alphanumeric characters
    if (!/[a-zA-Z0-9]/.test(signature)) {
        return { valid: false, error: 'Signature format is invalid' };
    }
    
    return { valid: true };
}

function validateClaimStructure(signedClaim) {
    // Check required fields
    if (!signedClaim.id) {
        return { valid: false, error: 'Claim ID is required' };
    }
    
    if (!signedClaim.data) {
        return { valid: false, error: 'Claim data is required' };
    }
    
    if (!signedClaim.data.wallets || !Array.isArray(signedClaim.data.wallets)) {
        return { valid: false, error: 'Wallets array is required' };
    }
    
    if (signedClaim.data.wallets.length === 0) {
        return { valid: false, error: 'At least one wallet is required' };
    }
    
    if (!signedClaim.data.spark_address) {
        return { valid: false, error: 'Spark address is required' };
    }
    
    if (!signedClaim.signature) {
        return { valid: false, error: 'Signature is required' };
    }
    
    if (!signedClaim.signed_by_wallet) {
        return { valid: false, error: 'Signed by wallet address is required' };
    }
    
    // Validate total_akitamia matches sum of wallet counts
    const calculatedTotal = signedClaim.data.wallets.reduce((sum, w) => sum + (w.akitamia_count || 0), 0);
    if (signedClaim.data.total_akitamia !== calculatedTotal) {
        return { valid: false, error: `Total Akitamia mismatch: claimed ${signedClaim.data.total_akitamia} but sum is ${calculatedTotal}` };
    }
    
    return { valid: true };
}

// Endpoint to save a signed claim
app.post('/api/save-claim', async (req, res) => {
    const client = await pool.connect();
    try {
        const signedClaim = req.body;
        
        console.log('🔍 Validating claim submission...');
        
        // STEP 1: Validate claim structure
        const structureCheck = validateClaimStructure(signedClaim);
        if (!structureCheck.valid) {
            console.error('❌ Validation failed - Invalid claim structure:', structureCheck.error);
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid claim submission. Please try again.'
            });
        }
        
        // STEP 2: Validate Spark address format
        const sparkCheck = validateSparkAddress(signedClaim.data.spark_address);
        if (!sparkCheck.valid) {
            console.error('❌ Validation failed - Invalid Spark address:', sparkCheck.error);
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid claim submission. Please try again.'
            });
        }
        
        // STEP 3: Validate signature format
        const signatureCheck = validateSignature(signedClaim.signature);
        if (!signatureCheck.valid) {
            console.error('❌ Validation failed - Invalid signature:', signatureCheck.error);
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid claim submission. Please try again.'
            });
        }
        
        // STEP 4: Validate signed_by_wallet address format
        const signerAddressCheck = validateBitcoinAddress(signedClaim.signed_by_wallet);
        if (!signerAddressCheck.valid) {
            console.error('❌ Validation failed - Invalid signer wallet address:', signerAddressCheck.error);
            return res.status(400).json({ 
                success: false, 
                message: 'Invalid claim submission. Please try again.'
            });
        }
        
        // STEP 5: Validate all wallet addresses and re-verify via Hiro API
        console.log('🔍 Re-verifying wallet ownership via Hiro API...');
        let totalVerifiedAkitamia = 0;
        
        for (const wallet of signedClaim.data.wallets) {
            // Validate address format
            const walletAddressCheck = validateBitcoinAddress(wallet.address);
            if (!walletAddressCheck.valid) {
                console.error(`❌ Validation failed - Invalid wallet address: ${wallet.address} - ${walletAddressCheck.error}`);
                return res.status(400).json({ 
                    success: false, 
                    message: 'Invalid claim submission. Please try again.'
                });
            }
            
            // Re-verify ownership via Hiro API
            const actualCount = await verifyWalletAkitamia(wallet.address);
            
            if (actualCount === null) {
                console.error(`❌ Blockchain verification failed for wallet: ${wallet.address}`);
                return res.status(503).json({ 
                    success: false, 
                    message: 'Unable to verify claim at this time. Please try again later.'
                });
            }
            
            // Check if claimed count matches actual blockchain count
            if (actualCount !== wallet.akitamia_count) {
                console.error(`❌ Akitamia count mismatch - Wallet: ${wallet.address}, Claimed: ${wallet.akitamia_count}, Actual: ${actualCount}`);
                return res.status(400).json({ 
                    success: false, 
                    message: 'Claim verification failed. Please reconnect your wallet and try again.'
                });
            }
            
            totalVerifiedAkitamia += actualCount;
            console.log(`   ✅ Verified: ${wallet.address} - ${actualCount} Akitamia`);
        }
        
        // STEP 6: Verify total matches
        if (totalVerifiedAkitamia !== signedClaim.data.total_akitamia) {
            console.error(`❌ Total Akitamia mismatch - Claimed: ${signedClaim.data.total_akitamia}, Verified: ${totalVerifiedAkitamia}`);
            return res.status(400).json({ 
                success: false, 
                message: 'Claim verification failed. Please reconnect your wallet and try again.'
            });
        }
        
        console.log('✅ All validations passed. Saving to database...');
        
        await client.query('BEGIN');
        
        // 7. Insert into claims table
        await client.query(`
            INSERT INTO claims (
                claim_id, spark_address, total_akitamia, 
                wallet_type, signed_by_wallet, signed_at, raw_signature
            ) VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (claim_id) DO NOTHING
        `, [
            signedClaim.id,
            signedClaim.data.spark_address,
            signedClaim.data.total_akitamia,
            signedClaim.wallet_type,
            signedClaim.signed_by_wallet,
            signedClaim.signed_at,
            signedClaim.signature
        ]);
        
        // 8. Insert wallets
        for (const wallet of signedClaim.data.wallets) {
            await client.query(`
                INSERT INTO wallets (claim_id, btc_address, akitamia_count)
                VALUES ($1, $2, $3)
                ON CONFLICT (claim_id, btc_address) DO NOTHING
            `, [
                signedClaim.id,
                wallet.address,
                wallet.akitamia_count
            ]);
        }
        
        // 9. Insert full JSON backup
        await client.query(`
            INSERT INTO claim_data (claim_id, full_json)
            VALUES ($1, $2)
            ON CONFLICT (claim_id) DO NOTHING
        `, [
            signedClaim.id,
            signedClaim
        ]);
        
        await client.query('COMMIT');
        
        console.log(`✅ Claim saved to database!`);
        console.log(`   Spark address: ${signedClaim.data.spark_address}`);
        console.log(`   Wallets: ${signedClaim.data.wallets.length}`);
        console.log(`   Total Akitamia: ${signedClaim.data.total_akitamia}`);
        
        res.json({ 
            success: true, 
            message: 'Claim submitted successfully!'
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ Error saving claim to database:');
        console.error('   Message:', error.message);
        console.error('   Detail:', error.detail);
        console.error('   Code:', error.code);
        console.error('   Full error:', error);
        
        // Check for specific database errors
        if (error.code === '23505') { // Unique constraint violation
            console.error('❌ Duplicate entry detected:', error.detail);
            return res.status(409).json({ 
                success: false, 
                message: 'This claim has already been submitted.'
            });
        }
        
        // Generic error for all other cases
        res.status(500).json({ 
            success: false, 
            message: 'Unable to process your claim at this time. Please try again later.'
        });
    } finally {
        client.release();
    }
});

// Endpoint to get all claims
app.get('/api/claims', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                c.*,
                json_agg(json_build_object(
                    'btc_address', w.btc_address,
                    'akitamia_count', w.akitamia_count
                )) as wallets
            FROM claims c
            LEFT JOIN wallets w ON c.claim_id = w.claim_id
            GROUP BY c.id
            ORDER BY c.created_at DESC
        `);
        
        res.json({ 
            success: true,
            claims: result.rows 
        });
    } catch (error) {
        console.error('Error fetching claims:', error);
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// Function to verify wallet Akitamia count using Hiro API
async function verifyWalletAkitamia(btcAddress) {
    const INSCRIPTION_RANGE = {
        min: 105831003,
        max: 105841545
    };
    
    return new Promise((resolve) => {
        const url = `https://api.hiro.so/ordinals/v1/inscriptions?address=${btcAddress}&limit=60`;
        
        https.get(url, (response) => {
            let data = '';
            
            response.on('data', (chunk) => {
                data += chunk;
            });
            
            response.on('end', () => {
                try {
                    if (response.statusCode !== 200) {
                        console.error(`Hiro API error for ${btcAddress}: ${response.statusCode}`);
                        resolve(null);
                        return;
                    }
                    
                    const jsonData = JSON.parse(data);
                    
                    if (jsonData.results && jsonData.results.length > 0) {
                        const akitamiaInscriptions = jsonData.results.filter(inscription => {
                            const num = inscription.number;
                            return num >= INSCRIPTION_RANGE.min && num <= INSCRIPTION_RANGE.max;
                        });
                        resolve(akitamiaInscriptions.length);
                    } else {
                        resolve(0);
                    }
                } catch (error) {
                    console.error(`Error parsing response for ${btcAddress}:`, error.message);
                    resolve(null);
                }
            });
        }).on('error', (error) => {
            console.error(`Error verifying wallet ${btcAddress}:`, error.message);
            resolve(null);
        });
    });
}

// Function to verify and update all wallets in a claim
async function verifyAndUpdateClaim(claimId, wallets) {
    const client = await pool.connect();
    let updatesNeeded = false;
    let newTotalAkitamia = 0;
    const updates = [];
    
    try {
        // Verify each wallet
        for (const wallet of wallets) {
            const currentCount = await verifyWalletAkitamia(wallet.btc_address);
            
            if (currentCount === null) {
                // API failed, skip this wallet
                newTotalAkitamia += wallet.akitamia_count;
                continue;
            }
            
            if (currentCount !== wallet.akitamia_count) {
                // Count changed, need to update
                updatesNeeded = true;
                updates.push({
                    address: wallet.btc_address,
                    oldCount: wallet.akitamia_count,
                    newCount: currentCount
                });
                
                // Update wallet in database
                await client.query(
                    'UPDATE wallets SET akitamia_count = $1 WHERE claim_id = $2 AND btc_address = $3',
                    [currentCount, claimId, wallet.btc_address]
                );
            }
            
            newTotalAkitamia += currentCount;
        }
        
        // If updates were needed, also update the total in claims table
        if (updatesNeeded) {
            await client.query(
                'UPDATE claims SET total_akitamia = $1 WHERE claim_id = $2',
                [newTotalAkitamia, claimId]
            );
            
            console.log(`📊 Updated claim ${claimId}: Total Akitamia ${newTotalAkitamia}`);
            updates.forEach(u => {
                console.log(`   - ${u.address}: ${u.oldCount} → ${u.newCount}`);
            });
        }
        
        return {
            updated: updatesNeeded,
            newTotal: newTotalAkitamia,
            updates: updates
        };
        
    } catch (error) {
        console.error('Error updating claim:', error);
        throw error;
    } finally {
        client.release();
    }
}

// Endpoint to get claim by spark address
app.get('/api/claims/spark/:address', async (req, res) => {
    try {
        const sparkAddress = req.params.address;
        
        const result = await pool.query(`
            SELECT 
                c.*,
                json_agg(json_build_object(
                    'btc_address', w.btc_address,
                    'akitamia_count', w.akitamia_count
                )) as wallets
            FROM claims c
            LEFT JOIN wallets w ON c.claim_id = w.claim_id
            WHERE c.spark_address = $1
            GROUP BY c.id
        `, [sparkAddress]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                success: false,
                message: 'No claim found for this Spark address' 
            });
        }
        
        const claim = result.rows[0];
        
        // Verify and update wallet counts using Hiro API
        console.log(`🔍 Verifying Akitamia counts for Spark address: ${sparkAddress}`);
        const verificationResult = await verifyAndUpdateClaim(claim.claim_id, claim.wallets);
        
        // Fetch updated data if changes were made
        let finalClaim = claim;
        if (verificationResult.updated) {
            const updatedResult = await pool.query(`
                SELECT 
                    c.*,
                    json_agg(json_build_object(
                        'btc_address', w.btc_address,
                        'akitamia_count', w.akitamia_count
                    )) as wallets
                FROM claims c
                LEFT JOIN wallets w ON c.claim_id = w.claim_id
                WHERE c.spark_address = $1
                GROUP BY c.id
            `, [sparkAddress]);
            
            finalClaim = updatedResult.rows[0];
        }
        
        res.json({ 
            success: true,
            claim: finalClaim,
            verified: true,
            updated: verificationResult.updated,
            verification_info: verificationResult.updated ? {
                message: 'Wallet counts were updated based on current blockchain data',
                updates: verificationResult.updates
            } : {
                message: 'All wallet counts are up to date'
            }
        });
    } catch (error) {
        console.error('Error fetching claim:', error);
        res.status(500).json({ 
            success: false,
            error: error.message 
        });
    }
});

// PUBLIC API ENDPOINT - For external platforms
// GET /api/v1/public/claim/:sparkAddress
// Returns claim data with verification in clean JSON format
app.get('/api/v1/public/claim/:sparkAddress', async (req, res) => {
    const clientIp = req.ip || req.connection.remoteAddress;
    const sparkAddress = req.params.sparkAddress;
    
    // Log the API access
    console.log(`📡 Public API Request - IP: ${clientIp} - Spark: ${sparkAddress} - Time: ${new Date().toISOString()}`);
    
    // Check rate limit
    if (!checkRateLimit(clientIp)) {
        console.log(`⚠️ Rate limit exceeded for IP: ${clientIp}`);
        return res.status(429).json({
            success: false,
            error: 'Rate limit exceeded',
            message: 'Too many requests. Please try again later.',
            rate_limit: {
                max_requests: RATE_LIMIT_MAX_REQUESTS,
                window: '1 hour'
            }
        });
    }
    
    try {
        // Query the database for the claim
        const result = await pool.query(`
            SELECT 
                c.*,
                json_agg(json_build_object(
                    'btc_address', w.btc_address,
                    'akitamia_count', w.akitamia_count
                )) as wallets
            FROM claims c
            LEFT JOIN wallets w ON c.claim_id = w.claim_id
            WHERE c.spark_address = $1
            GROUP BY c.id
        `, [sparkAddress]);
        
        if (result.rows.length === 0) {
            console.log(`❌ No claim found for Spark: ${sparkAddress}`);
            return res.status(404).json({ 
                success: false,
                api_version: '1.0',
                queried_at: new Date().toISOString(),
                spark_address: sparkAddress,
                message: 'No claim found for this Spark address'
            });
        }
        
        const claim = result.rows[0];
        
        // Verify and update wallet counts using Hiro API
        console.log(`🔍 Verifying Akitamia counts for public API request: ${sparkAddress}`);
        const verificationResult = await verifyAndUpdateClaim(claim.claim_id, claim.wallets);
        
        // Fetch updated data if changes were made
        let finalClaim = claim;
        if (verificationResult.updated) {
            const updatedResult = await pool.query(`
                SELECT 
                    c.*,
                    json_agg(json_build_object(
                        'btc_address', w.btc_address,
                        'akitamia_count', w.akitamia_count
                    )) as wallets
                FROM claims c
                LEFT JOIN wallets w ON c.claim_id = w.claim_id
                WHERE c.spark_address = $1
                GROUP BY c.id
            `, [sparkAddress]);
            
            finalClaim = updatedResult.rows[0];
        }
        
        // Format wallets array for public API
        const formattedWallets = finalClaim.wallets.map(w => ({
            address: w.btc_address,
            akitamia_count: w.akitamia_count
        }));
        
        // Return clean, formatted response
        const response = {
            success: true,
            api_version: '1.0',
            queried_at: new Date().toISOString(),
            spark_address: finalClaim.spark_address,
            claim: {
                total_akitamia: finalClaim.total_akitamia,
                wallet_count: formattedWallets.length,
                signed_at: finalClaim.signed_at,
                signed_by_wallet: finalClaim.signed_by_wallet,
                wallet_type: finalClaim.wallet_type,
                wallets: formattedWallets
            },
            verification: {
                verified_at: new Date().toISOString(),
                blockchain_verified: true,
                data_updated: verificationResult.updated,
                message: verificationResult.updated 
                    ? 'Wallet counts were updated based on current blockchain data' 
                    : 'All wallet counts are up to date',
                updates: verificationResult.updated ? verificationResult.updates : []
            }
        };
        
        console.log(`✅ Public API Response sent for: ${sparkAddress}`);
        res.json(response);
        
    } catch (error) {
        console.error(`❌ Error in public API for ${sparkAddress}:`, error);
        res.status(500).json({ 
            success: false,
            api_version: '1.0',
            queried_at: new Date().toISOString(),
            error: 'Internal server error',
            message: 'Failed to process request. Please try again later.'
        });
    }
});

// Endpoint to check if a wallet address has already been used for signing
app.get('/api/check-wallet/:address', async (req, res) => {
    try {
        const walletAddress = req.params.address;
        
        // Check if this address has already signed a claim
        const signedResult = await pool.query(`
            SELECT 
                c.spark_address,
                c.total_akitamia,
                c.signed_at,
                c.claim_id
            FROM claims c
            WHERE c.signed_by_wallet = $1
        `, [walletAddress]);
        
        if (signedResult.rows.length > 0) {
            // Wallet has already been used for signing
            console.log(`ℹ️ Wallet already used for signing: ${walletAddress}`);
            return res.json({ 
                success: true,
                already_used: true,
                message: 'This wallet has already been used.'
            });
        }
        
        // Check if this address exists in wallets table (part of another claim)
        const walletResult = await pool.query(`
            SELECT 
                w.akitamia_count,
                c.spark_address,
                c.signed_by_wallet
            FROM wallets w
            JOIN claims c ON w.claim_id = c.claim_id
            WHERE w.btc_address = $1
        `, [walletAddress]);
        
        if (walletResult.rows.length > 0) {
            // Wallet is already part of another claim
            console.log(`ℹ️ Wallet already in another claim: ${walletAddress}`);
            return res.json({ 
                success: true,
                already_used: true,
                message: 'This wallet has already been used.'
            });
        }
        
        // Wallet is available to use
        res.json({ 
            success: true,
            already_used: false,
            message: 'This wallet is available to use'
        });
        
    } catch (error) {
        console.error('❌ Error checking wallet:', error.message);
        res.status(500).json({ 
            success: false,
            message: 'Unable to check wallet status. Please try again.'
        });
    }
});

// Endpoint to check if a Spark address has already been used
app.get('/api/check-spark/:address', async (req, res) => {
    try {
        const sparkAddress = req.params.address;
        
        const result = await pool.query(`
            SELECT 
                c.total_akitamia,
                c.signed_at,
                c.signed_by_wallet,
                COUNT(w.id) as wallet_count
            FROM claims c
            LEFT JOIN wallets w ON c.claim_id = w.claim_id
            WHERE c.spark_address = $1
            GROUP BY c.id, c.total_akitamia, c.signed_at, c.signed_by_wallet
        `, [sparkAddress]);
        
        if (result.rows.length > 0) {
            console.log(`ℹ️ Spark address already used: ${sparkAddress}`);
            return res.json({ 
                success: true,
                already_used: true,
                message: 'This Spark address has already been used.'
            });
        }
        
        res.json({ 
            success: true,
            already_used: false,
            message: 'This Spark address is available.'
        });
        
    } catch (error) {
        console.error('❌ Error checking Spark address:', error.message);
        res.status(500).json({ 
            success: false,
            message: 'Unable to check Spark address. Please try again.'
        });
    }
});

// Endpoint to authenticate access to airdrop page
app.post('/api/auth/login', (req, res) => {
    const clientIp = req.ip || req.connection.remoteAddress;
    
    // Rate limiting for login attempts
    if (!checkRateLimit(clientIp)) {
        console.log(`⚠️ Rate limit exceeded for login attempt - IP: ${clientIp}`);
        return res.status(429).json({
            success: false,
            message: 'Too many login attempts. Please try again later.'
        });
    }
    
    try {
        const { username, password } = req.body;
        
        const correctUsername = process.env.AIRDROP_USERNAME || 'admin';
        const correctPassword = process.env.AIRDROP_PASSWORD || 'akitamia2025';
        
        if (username === correctUsername && password === correctPassword) {
            console.log(`✅ Successful login attempt - IP: ${clientIp}`);
            return res.json({
                success: true,
                message: 'Authentication successful'
            });
        }
        
        console.log(`❌ Failed login attempt - IP: ${clientIp}`);
        res.status(401).json({
            success: false,
            message: 'Invalid credentials'
        });
        
    } catch (error) {
        console.error('❌ Authentication error:', error.message);
        res.status(500).json({
            success: false,
            message: 'Authentication failed. Please try again.'
        });
    }
});

app.listen(PORT, () => {
    console.log(`\n🚀 Claim server running on http://localhost:${PORT}`);
    console.log(`📊 Database: akitamia_airdrop`);
    console.log(`🔐 Airdrop page authentication: ${process.env.AIRDROP_USERNAME ? 'ENABLED' : 'DISABLED'}`);
    console.log(`� All claims stored in PostgreSQL\n`);
});
