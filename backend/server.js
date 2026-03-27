const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const compression = require("compression"); // Added for faster data transfer
const { OAuth2Client } = require("google-auth-library");
const nodemailer = require("nodemailer");
require("dotenv").config();

const app = express();
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);
const apiCache = new Map();
const CACHE_TTL_MS = 5 * 60 * 1000;

// --- PERFORMANCE MIDDLEWARE ---
const allowedOrigins = ['https://metroclassy-ten.vercel.app/home.html','https://metroclassy-metro.vercel.app', 'https://metroclassy-admin.vercel.app', 'http://localhost:5500'];
app.use(cors({
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    }
}));

app.use(compression()); // Compresses JSON responses to load faster on frontend
app.use(express.json({ limit: "10mb" })); // Reduced from 50mb for better memory safety
app.use(express.urlencoded({ limit: "10mb", extended: true }));

// --- DATABASE HANDSHAKE (OPTIMIZED POOLING) ---
const dbOptions = {
    maxPoolSize: 10, // Maintain up to 10 socket connections for parallel queries
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
};

let isConnected = false;
const connectDB = async () => {
    if (isConnected) {
        console.log("=> using existing database connection");
        return;
    }
    try {
        const db = await mongoose.connect(process.env.MONGO_URI, dbOptions);
        isConnected = db.connections[0].readyState;
        console.log("✅ Database Uplink Established | Pooling Active (Cached)");
    } catch (err) {
        console.error("❌ Database Connection Failed:", err);
    }
};
connectDB();

// --- MODELS (Kept exactly as provided) ---
const Collection = mongoose.model("Collection", new mongoose.Schema({
    name: { type: String, required: true, unique: true },
    isActive: { type: Boolean, default: true },
}));

const Category = mongoose.model("Category", new mongoose.Schema({
    name: { type: String, required: true },
    parentCollection: { type: mongoose.Schema.Types.ObjectId, ref: "Collection", required: true },
}));

// Added Indexing for faster search/filter
const productSchema = new mongoose.Schema({
    name: { type: String, index: true }, 
    description: String,
    mrp: Number,
    salePrice: Number,
    stock: Object, 
    colors: Array,
    media: Array, 
    collectionId: { type: mongoose.Schema.Types.ObjectId, ref: "Collection", index: true },
    categoryId: { type: mongoose.Schema.Types.ObjectId, ref: "Category", index: true },
    tags: String,
    isArchived: { type: Boolean, default: false, index: true }, 
    dateDeployed: { type: Date, default: Date.now },
    reviews: [{
        userId: mongoose.Schema.Types.ObjectId,
        userName: String,
        rating: Number,
        text: String,
        date: { type: Date, default: Date.now }
    }]
});
const Product = mongoose.model("Product", productSchema);

const User = mongoose.model("User", new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true, index: true },
    password: { type: String, required: true },
    role: { type: String, default: "citizen" },
    isVerified: { type: Boolean, default: true },
    dateJoined: { type: Date, default: Date.now }
}));

const Admin = mongoose.model("Admin", new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
}), "admin"); 

const Order = mongoose.model("Order", new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, index: true },
    items: Array,
    address: Object,
    totalAmount: Number,
    paymentMethod: String,
    status: { type: String, default: "Progress", index: true }, 
    trackingLink: { type: String, default: "" },   
    date: { type: Date, default: Date.now, index: true }
}));

const Coupon = mongoose.model("Coupon", new mongoose.Schema({
    code: { type: String, required: true, unique: true },
    type: { type: String, enum: ['percentage', 'flat'], default: 'flat' },
    value: { type: Number, required: true },
    startDate: Date,
    endDate: Date,
    totalLimit: { type: Number, default: 100 },
    userLimit: { type: Number, default: 1 },
    minCart: { type: Number, default: 0 },
    usedCount: { type: Number, default: 0 },
    isActive: { type: Boolean, default: true }
}));

const Hero = mongoose.model("Hero", new mongoose.Schema({
    mediaUrl: String,
    mediaType: { type: String, enum: ['image', 'video'] },
    productId: { type: mongoose.Schema.Types.ObjectId, ref: "Product" },
    slot: { type: Number, unique: true } 
}));

// --- MIDDLEWARE ---
const adminGuard = async (req, res, next) => {
    const userId = req.headers['admin-signal']; 
    if (!userId) return res.status(401).json({ error: "ACCESS DENIED: NO SIGNAL" });
    try {
        const admin = await User.findById(userId).select('role').lean(); // Optimization: Only fetch role, skip Mongoose overhead
        if (admin && admin.role === 'admin') return next();
        res.status(403).json({ error: "FORBIDDEN: ADMIN CLEARANCE REQUIRED" });
    } catch (e) { res.status(500).json({ error: "Guard System Fault" }); }
};

const transporter = nodemailer.createTransport({
    service: "gmail",
    pool: true, // Use pooled connections for sending multiple emails
    auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS 
    }
});

const otpVault = new Map();

// --- SYSTEM ROUTES ---
app.get("/ping", (req, res) => res.send("pong"));

// --- AUTH ROUTES ---

app.post("/api/auth/forgot-password", async (req, res) => {
    const { email } = req.body;
    try {
        const user = await User.findOne({ email }).select('_id').lean();
        if (!user) return res.status(404).json({ error: "Identity not found." });

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        otpVault.set(email, { otp, expires: Date.now() + 600000 });

        transporter.sendMail({
            from: '"METROCLASSY HQ" <metroclassy1223@gmail.com>',
            to: email,
            subject: "PASSWORD RESET SIGNAL",
            html: `<h1>VERIFICATION CODE: ${otp}</h1>`
        }).catch(err => console.error("Background Mail Error:", err)); 

        res.json({ success: true, message: "Transmission initiated." });
    } catch (err) { res.status(500).json({ error: "Internal Error" }); }
});

app.post("/api/auth/reset-password", async (req, res) => {
    const { email, otp, newPassword } = req.body;
    const record = otpVault.get(email);
    if (!record || record.otp !== otp || Date.now() > record.expires) {
        return res.status(400).json({ error: "Invalid or expired signal." });
    }
    try {
        await User.updateOne({ email }, { password: newPassword });
        otpVault.delete(email); 
        res.json({ success: true, message: "Credentials Updated." });
    } catch (err) { res.status(500).json({ error: "Vault Update Failed" }); }
});

app.get("/api/sector-data", async (req, res) => {
    try {
        const [collections, categories, coupons] = await Promise.all([
            Collection.find().lean(),
            Category.find().populate("parentCollection").lean(),
            Coupon.find({ isActive: true }).sort({ endDate: -1 }).lean()
        ]);
        res.json({ collections, categories, coupons });
    } catch (err) { res.status(500).json({ error: "Sector Data Signal Lost" }); }
});

app.post("/api/auth/google", async (req, res) => {
    try {
        const { token } = req.body;
        const ticket = await googleClient.verifyIdToken({
            idToken: token,
            audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        
        let user = await User.findOne({ email: payload.email });
        if (!user) {
            user = new User({
                name: payload.name,
                email: payload.email,
                password: "GOOGLE_AUTH_USER",
                role: "citizen",
                isVerified: true
            });
            await user.save();
        }
        res.json({ success: true, user: { name: user.name, email: user.email, role: user.role, id: user._id } });
    } catch (err) { res.status(401).json({ error: "Google Auth Failed" }); }
});

app.post("/api/auth/signup", async (req, res) => {
    try {
        const { name, email, password } = req.body;
        const existing = await User.findOne({ email }).select('_id').lean();
        if (existing) return res.status(400).json({ error: "Comm-link already in archives." });
        const newUser = new User({ name, email, password, isVerified: true });
        await newUser.save();
        res.status(201).json({ success: true, user: { name: newUser.name, email: newUser.email, role: newUser.role, id: newUser._id } });
    } catch (err) { res.status(400).json({ error: "Enlistment Failure" }); }
});

app.post("/api/auth/admin-login", async (req, res) => {
    try {
        const { email, password, secureCode } = req.body;
        const MASTER_SECURE_CODE = "774921";
        const adminRecord = await Admin.findOne({ email }).lean();
        
        if (adminRecord && adminRecord.password === password) {
            if (!secureCode || secureCode !== MASTER_SECURE_CODE) {
                return res.status(403).json({ error: "SECURE CODE REQUIRED", step: 2 });
            }
            let adminUser = await User.findOne({ email: adminRecord.email });
            if(!adminUser) {
                adminUser = new User({ name: "Admin_Root", email: adminRecord.email, password: adminRecord.password, role: "admin" });
                await adminUser.save();
            }
            return res.json({ success: true, user: { name: "Admin_Root", email: adminRecord.email, role: "admin", id: adminUser._id } });
        }
        res.status(401).json({ error: "INVALID IDENTITY" });
    } catch (err) { res.status(500).json({ error: "Vault Offline" }); }
});

app.post("/api/auth/login", async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email, password }).lean();
        if (!user) return res.status(401).json({ error: "Invalid Credentials" });
        if (user.role === 'admin') {
            return res.status(403).json({ error: "ADMIN CLEARANCE DETECTED: Use the Admin Terminal to log in." });
        }
        res.json({ success: true, user: { name: user.name, email: user.email, role: user.role, id: user._id } });
    } catch (err) { res.status(500).json({ error: "Vault Communication Error" }); }
});

// --- PRODUCT & REVIEW ROUTES ---

app.post("/api/products/:id/reviews", async (req, res) => {
    try {
        const { userId, userName, rating, text } = req.body;
        const product = await Product.findById(req.params.id);
        if (!product) return res.status(404).json({ error: "Gear Not Found" });
        product.reviews.unshift({ userId, userName, rating, text });
        await product.save();
        res.json(product);
    } catch (err) { res.status(500).json({ error: "Feedback Sync Failed" }); }
});

app.get("/api/products", async (req, res) => {
    try {
        const cacheKey = req.originalUrl;
        if (apiCache.has(cacheKey)) {
            const cached = apiCache.get(cacheKey);
            if (Date.now() - cached.time < CACHE_TTL_MS) return res.json(cached.data);
        }

        let query = { isArchived: false }; 
        if (req.query.search) query.name = { $regex: req.query.search, $options: 'i' };
        if (req.query.collection) query.collectionId = req.query.collection;
        if (req.query.category) query.categoryId = req.query.category;
        
        let sort = req.query.sort === 'price-low' ? { salePrice: 1 } : req.query.sort === 'price-high' ? { salePrice: -1 } : { dateDeployed: -1 };
        
        const products = await Product.find(query)
            .populate("collectionId categoryId")
            .sort(sort)
            .lean(); // Faster JSON conversion
        apiCache.set(cacheKey, { data: products, time: Date.now() });
        res.json(products);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/products/:id", async (req, res) => {
    try {
        const product = await Product.findById(req.params.id).populate("collectionId categoryId").lean();
        res.json(product);
    } catch (err) { res.status(404).json({ error: "Gear Not Found" }); }
});

app.get("/api/heroes", async (req, res) => {
    try {
        const heroes = await Hero.find().populate("productId").sort({ slot: 1 }).lean();
        res.json(heroes);
    } catch (err) { res.status(500).json({ error: err.message }); }
});

// --- ORDER HANDLING ---

app.post("/api/orders/deploy", async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const { items, address, totalAmount, paymentMethod, userId, couponCode } = req.body;
        const order = new Order({ userId, items, address, totalAmount, paymentMethod });
        await order.save({ session });

        for (const item of items) {
            const product = await Product.findById(item.id || item._id).session(session);
            if (product && product.stock) {
                const requestedQty = item.quantity || 1;
                if (product.stock[item.size] < requestedQty) throw new Error(`Insufficient stock for ${product.name}`);
                product.stock[item.size] -= requestedQty;
                product.markModified('stock'); 
                await product.save({ session });
            }
        }
        if (couponCode) {
            await Coupon.updateOne({ code: couponCode.toUpperCase() }, { $inc: { usedCount: 1 } }, { session });
        }
        await session.commitTransaction();
        res.status(201).json({ success: true, orderId: order._id });
    } catch (err) {
        await session.abortTransaction();
        res.status(400).json({ error: err.message });
    } finally { session.endSession(); }
});

// --- ADMIN SECURED ROUTES ---

app.get("/api/admin/hq-stats", adminGuard, async (req, res) => {
    try {
        const [orders, gearCount, citizenCount] = await Promise.all([
            Order.aggregate([{ $match: { status: { $ne: "Aborted" } } }, { $group: { _id: null, total: { $sum: "$totalAmount" } } }]),
            Product.countDocuments({ isArchived: false }),
            User.countDocuments()
        ]);
        res.json({
            revenue: orders[0]?.total || 0,
            gear: gearCount,
            citizens: citizenCount,
            recentOrders: await Order.find().sort({ date: -1 }).limit(5).lean()
        });
    } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get("/api/admin/all-reviews", adminGuard, async (req, res) => {
    try {
        const products = await Product.find({ "reviews.0": { $exists: true } }, 'name reviews').lean();
        const allReviews = products.flatMap(p => p.reviews.map(r => ({
            productId: p._id,
            productName: p.name,
            reviewId: r._id,
            userName: r.userName,
            rating: r.rating,
            text: r.text,
            date: r.date
        })));
        res.json(allReviews.sort((a, b) => b.date - a.date));
    } catch (err) { res.status(500).json({ error: "Moderation Signal Lost" }); }
});

app.delete("/api/admin/products/:pid/reviews/:rid", adminGuard, async (req, res) => {
    try {
        await Product.updateOne({ _id: req.params.pid }, { $pull: { reviews: { _id: req.params.rid } } });
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: "Termination Failed" }); }
});

// --- MISC ROUTES (LEAN OPTIMIZED) ---

app.get("/api/track/:id", async (req, res) => {
    try {
        const { id } = req.params;
        let order = (id.length === 24) ? await Order.findById(id).lean() : null;
        if (!order) {
            const allOrders = await Order.find().lean();
            order = allOrders.find(o => o._id.toString().toUpperCase().endsWith(id.toUpperCase()));
        }
        if (!order) return res.status(404).json({ error: "Signal Not Found" });
        res.json(order);
    } catch (err) { res.status(500).json({ error: "Track Signal Lost" }); }
});

app.patch("/api/orders/:id/abort", async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    try {
        const order = await Order.findOne({ _id: req.params.id, userId: req.body.userId }).session(session);
        if (!order || order.status !== 'Progress') throw new Error("Abort Denied");

        for (const item of order.items) {
            await Product.updateOne(
                { _id: item.id || item._id }, 
                { $inc: { [`stock.${item.size}`]: item.quantity || 1 } },
                { session }
            );
        }
        order.status = 'Aborted';
        await order.save({ session });
        await session.commitTransaction();
        res.json({ success: true, message: "MISSION TERMINATED & ASSETS RESTORED" });
    } catch (err) {
        await session.abortTransaction();
        res.status(500).json({ error: err.message });
    } finally { session.endSession(); }
});

// Admin Control (Fast Routes)
app.post("/api/collections", adminGuard, async (req, res) => { const col = new Collection(req.body); await col.save(); res.json(col); });
app.delete("/api/collections/:id", adminGuard, async (req, res) => { 
    await Promise.all([Category.deleteMany({ parentCollection: req.params.id }), Collection.findByIdAndDelete(req.params.id)]);
    res.json({ success: true }); 
});
app.post("/api/categories", adminGuard, async (req, res) => { const cat = new Category(req.body); await cat.save(); res.json(cat); });
app.delete("/api/categories/:id", adminGuard, async (req, res) => { await Category.findByIdAndDelete(req.params.id); res.json({ success: true }); });
app.post("/api/admin/deploy", adminGuard, async (req, res) => { const p = new Product(req.body); await p.save(); res.status(201).json({ success: true }); });
app.get("/api/admin/all-products", adminGuard, async (req, res) => { res.json(await Product.find().populate("collectionId categoryId").sort({ dateDeployed: -1 }).lean()); });
app.put("/api/admin/products/:id", adminGuard, async (req, res) => { res.json(await Product.findByIdAndUpdate(req.params.id, req.body, { new: true }).lean()); });
app.delete("/api/admin/products/:id", adminGuard, async (req, res) => { await Product.findByIdAndDelete(req.params.id); res.json({ success: true }); });
app.post("/api/admin/coupons", adminGuard, async (req, res) => { const cp = new Coupon(req.body); await cp.save(); res.status(201).json(cp); });
app.delete("/api/admin/coupons/:id", adminGuard, async (req, res) => { await Coupon.findByIdAndDelete(req.params.id); res.json({ success: true }); });

app.post("/api/validate-coupon", async (req, res) => {
    try {
        const { code, cartValue } = req.body;
        const coupon = await Coupon.findOne({ code: code.toUpperCase(), isActive: true }).lean();
        if (!coupon) return res.status(400).json({ valid: false, message: "SIGNAL NOT FOUND" });
        if (coupon.usedCount >= coupon.totalLimit) return res.status(400).json({ valid: false, message: "VOUCHER DEPLETED" });
        if (cartValue < coupon.minCart) return res.status(400).json({ valid: false, message: `MINIMUM ₹${coupon.minCart} REQUIRED` });
        res.json({ valid: true, discount: coupon.value, type: coupon.type });
    } catch (err) { res.status(500).json({ error: "Validation Interrupted" }); }
});

app.post("/api/admin/hero-deploy", adminGuard, async (req, res) => { await Hero.findOneAndUpdate({ slot: req.body.slot }, req.body, { upsert: true, new: true }); res.json({ success: true }); });
app.delete("/api/admin/hero/:slot", adminGuard, async (req, res) => { await Hero.findOneAndDelete({ slot: req.params.slot }); res.json({ success: true }); });
app.get("/api/admin/orders", adminGuard, async (req, res) => { res.json(await Order.find().sort({ date: -1 }).lean()); });
app.patch("/api/admin/orders/:id/status", adminGuard, async (req, res) => { res.json(await Order.findByIdAndUpdate(req.params.id, req.body, { new: true }).lean()); });
app.patch("/api/admin/orders/:id/link", adminGuard, async (req, res) => { res.json(await Order.findByIdAndUpdate(req.params.id, { trackingLink: req.body.link }, { new: true }).lean()); });
app.delete("/api/admin/orders/:id", adminGuard, async (req, res) => { await Order.findByIdAndDelete(req.params.id); res.json({ success: true }); });

app.get("/api/orders/user/:userId", async (req, res) => {
    try {
        res.json(await Order.find({ userId: req.params.userId }).sort({ date: -1 }).lean());
    } catch (err) { res.status(500).json({ error: "Signal Lost" }); }
});

app.listen(5000, () => console.log("🚀 Syndicate Hangar Online | Port 5000"));
