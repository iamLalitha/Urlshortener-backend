const mongoose = require('mongoose');

const Schema = mongoose.Schema;

const urlSchema = new Schema({
    title:{ type:String},
    longurl: {type: String},
    shorturl:{type:String, unique:true},
    shortid:{type:String},
    clicks:{type:Number, default:0},
    createdon:{type: String, default:String(new Date()).slice(4,15)},
    user:{type: Schema.Types.ObjectId, ref:"user"},
});

module.exports = mongoose.model("Url", urlSchema);
