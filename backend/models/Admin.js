const mongoose = require('mongoose');
const AdminSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});
module.exports = mongoose.model('Admin', AdminSchema, 'admin'); 
// The third argument 'admin' forces it to use your new collection