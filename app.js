const EXAMS={
dtm:{name:"Вступительный в вуз (ДТМ)",q:[
{t:"Решите уравнение: 2x + 6 = 20. Чему равен x?",o:["5","6","7","8"],a:2,e:"2x = 20 − 6 = 14, значит x = 7."},
{t:"Сколько будет 15% от 240?",o:["30","36","40","24"],a:1,e:"240 × 0,15 = 36."},
{t:"Площадь квадрата со стороной 9 см равна…",o:["18 см²","36 см²","81 см²","72 см²"],a:2,e:"Площадь квадрата = сторона², то есть 9 × 9 = 81."},
{t:"Choose the correct form: She ___ to school every day.",o:["go","goes","going","gone"],a:1,e:"С she/he/it в Present Simple к глаголу добавляется -s: goes."}]},
college:{name:"Колледжи и техникумы",q:[
{t:"Сколько будет 3/4 + 1/4?",o:["1","3/8","4/8","1/2"],a:0,e:"Знаменатели равны: (3 + 1)/4 = 4/4 = 1."},
{t:"Сколько минут в 2,5 часах?",o:["120","150","180","200"],a:1,e:"2,5 × 60 = 150 минут."},
{t:"Периметр прямоугольника со сторонами 5 и 3 равен…",o:["8","15","16","30"],a:2,e:"P = 2 × (5 + 3) = 16."}]}};
const SOON=["IELTS","SAT","Сейфер"];
const ls=(k,d)=>{try{return JSON.parse(localStorage.getItem(k))??d}catch{return d}};
const save=(k,v)=>{try{localStorage.setItem(k,JSON.stringify(v))}catch{}};
const me=()=>ls("ep_user",null),users=()=>ls("ep_users",{});
function addPoints(n){const u=me();if(!u)return false;const all=users();all[u.name]=(all[u.name]||0)+n;save("ep_users",all);return true}
document.body.insertAdjacentHTML("afterbegin",`<header><div><b>Подготовка к экзамену</b><a href="index.html">Главная</a><a href="exams.html">Экзамены</a><a href="rating.html">Рейтинг</a><a href="login.html">${me()?me().name:"Войти"}</a></div></header>`);
