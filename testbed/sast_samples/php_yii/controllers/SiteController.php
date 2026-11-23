<?php
// Intentionally vulnerable Yii 2 controller (academic SAST target).
namespace app\controllers;

use yii\web\Controller;

class SiteController extends Controller
{
    public function actionView()
    {
        $id = Yii::$app->request->get('id');
        $rows = Yii::$app->db
            ->createCommand("SELECT * FROM post WHERE id = " . $id)   // VULN: SQL injection
            ->queryAll();

        echo $id;                                                     // VULN: reflected XSS

        return $this->render('view', ['rows' => $rows]);
    }

    public function actionSafe()
    {
        $id = (int) Yii::$app->request->get('id');                    // cast -> safe
        $rows = Yii::$app->db
            ->createCommand("SELECT * FROM post WHERE id = :id")      // parameterized -> safe
            ->bindValue(':id', $id)
            ->queryAll();

        echo \yii\helpers\Html::encode($id);                         // encoded -> safe
        return $this->render('view', ['rows' => $rows]);
    }
}
